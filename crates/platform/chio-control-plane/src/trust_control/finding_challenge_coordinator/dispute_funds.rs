// Dispute fee and bond movements against the authoritative journal.

impl FindingChallengeCoordinator {
    /// Charge the dispute fee to the challenge-administration pool
    /// exactly once, through the same fence-then-dispatch-then-reconcile
    /// shape the shipped participation charge uses.
    ///
    /// The fee lives on the challenge lane's own effect fence rather than
    /// the admission fee ledger: that ledger is keyed by a closed event
    /// vocabulary whose two members are hard-pinned to the audit pool, so
    /// a dispute filing borrowing one of those keys would collide with the
    /// seller's own publication or participation charge for the same
    /// finding and listing, and settle nothing.
    fn charge_dispute_fee(
        &self,
        challenge_id: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        now: u64,
    ) -> Result<String, ChallengeCoordinatorError> {
        let fee = &submission.dispute_fee_terminal;
        let intent_key = dispute_fee_intent_key(challenge_id);
        let instruction = FindingRailInstruction {
            idempotency_key: intent_key.clone(),
            payer: fee.payer.to_hex(),
            amount_units: fee.amount.units,
            currency: fee.amount.currency.clone(),
            pool_principal_id: fee.beneficiary_pool_principal_id.clone(),
            rail_destination: fee.rail_destination.clone(),
        };
        // The commitment is the whole instruction, so a replay that names
        // a different amount, currency, pool, or destination collides with
        // what is already durable and rejects rather than charging twice
        // under one identity.
        let intent_digest = canonical_digest_of(&instruction)?;
        let fenced = self
            .challenges
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::Fee,
                &intent_digest,
                None,
                false,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if fenced == FindingChallengeWriteOutcome::ExistingSame {
            let state = self
                .challenges
                .get_effect_intent(&intent_key)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .map(|record| record.state);
            if state == Some(FindingEffectIntentState::Confirmed) {
                // Settled by an earlier attempt: dispatching again would
                // ask the rail to move the same money twice.
                return Ok(intent_key);
            }
        }
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        match self.rail.dispatch(&instruction) {
            Ok(observation)
                if rail_observation_matches(&instruction, &intent_digest, &observation) =>
            {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(intent_key)
            }
            Ok(_) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::FeeRail(
                    "rail observation does not reconcile to the dispatched instruction".to_owned(),
                ))
            }
            Err(reason) => {
                // The intent stays durable and unreconciled, so the filing
                // cannot proceed on an uncollected fee, and a retry
                // re-dispatches from `failed` rather than fencing again.
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::FeeRail(reason))
            }
        }
    }

    /// Compensate a collected dispute fee when the paired bond never
    /// funded before the signed filing horizon closed.
    fn return_dispute_fee(
        &self,
        challenge_id: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        pool: &chio_finding::FindingPoolBinding,
        now: u64,
    ) -> Result<(String, String), ChallengeCoordinatorError> {
        let fee = &submission.dispute_fee_terminal;
        let intent_key = dispute_fee_return_intent_key(challenge_id);
        let instruction = FindingRailInstruction {
            idempotency_key: intent_key.clone(),
            payer: pool.principal_id.clone(),
            amount_units: fee.amount.units,
            currency: fee.amount.currency.clone(),
            pool_principal_id: pool.principal_id.clone(),
            rail_destination: fee.payer.to_hex(),
        };
        let intent_digest = canonical_digest_of(&instruction)?;
        let fenced = self
            .challenges
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::Fee,
                &intent_digest,
                None,
                false,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if fenced == FindingChallengeWriteOutcome::ExistingSame {
            let state = self
                .challenges
                .get_effect_intent(&intent_key)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .map(|record| record.state);
            if state == Some(FindingEffectIntentState::Confirmed) {
                return Ok((intent_key, intent_digest));
            }
        }
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        match self.rail.dispatch(&instruction) {
            Ok(observation)
                if rail_observation_matches(&instruction, &intent_digest, &observation) =>
            {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok((intent_key, intent_digest))
            }
            Ok(_) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::FeeRail(
                    "fee return observation does not reconcile to the dispatched instruction"
                        .to_owned(),
                ))
            }
            Err(reason) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::FeeRail(reason))
            }
        }
    }

    fn fund_dispute_bond(
        &self,
        challenge_id: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        pool: &chio_finding::FindingPoolBinding,
        locked_at: u64,
        now: u64,
    ) -> Result<String, ChallengeCoordinatorError> {
        let lock = &submission.dispute_lock_ref;
        let owner_hex = submission.challenger.to_hex();
        let input = FindingDisputeLockInput {
            lock_id: &lock.lock_id,
            challenge_id,
            owner_hex: &owner_hex,
            schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
            amount_units: lock.amount.units,
            currency: &lock.amount.currency,
            pool_principal_id: &pool.principal_id,
            pool_rail_destination: &pool.rail_destination,
            pool_authority_epoch: pool.authority_epoch,
            expires_at: lock.expiry,
            locked_at,
        };
        let intent_key = derive_dispute_bond_funding_intent_key(challenge_id, &lock.lock_id);
        let intent_digest = dispute_bond_funding_intent_digest(&input);
        let fenced = self
            .challenges
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::ChallengeBond,
                &intent_digest,
                None,
                false,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if fenced == FindingChallengeWriteOutcome::ExistingSame {
            let state = self
                .challenges
                .get_effect_intent(&intent_key)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .map(|record| record.state);
            if state == Some(FindingEffectIntentState::Confirmed) {
                return Ok(intent_key);
            }
        }
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let instruction = FindingRailInstruction {
            idempotency_key: intent_key.clone(),
            payer: submission.challenger.to_hex(),
            amount_units: lock.amount.units,
            currency: lock.amount.currency.clone(),
            pool_principal_id: pool.principal_id.clone(),
            rail_destination: pool.rail_destination.clone(),
        };
        let instruction_digest = canonical_digest_of(&instruction)?;
        match self.rail.dispatch(&instruction) {
            Ok(observation)
                if rail_observation_matches(&instruction, &instruction_digest, &observation) =>
            {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(intent_key)
            }
            Ok(_) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::DisputeBondRail(
                    "rail observation does not reconcile to the dispatched instruction".to_owned(),
                ))
            }
            Err(reason) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::DisputeBondRail(reason))
            }
        }
    }

    /// Reconcile the reverse rail instruction before reporting a funded
    /// lock as returned. The distinct effect key makes the credit replay
    /// safe without confusing it with the original debit.
    fn return_dispute_bond(
        &self,
        lock: &FindingDisputeLockRecord,
        now: u64,
    ) -> Result<String, ChallengeCoordinatorError> {
        let input = FindingDisputeLockInput {
            lock_id: &lock.lock_id,
            challenge_id: &lock.challenge_id,
            owner_hex: &lock.owner_hex,
            schedule_envelope_sha256: &lock.schedule_envelope_sha256,
            amount_units: lock.amount_units,
            currency: &lock.currency,
            pool_principal_id: &lock.pool_principal_id,
            pool_rail_destination: &lock.pool_rail_destination,
            pool_authority_epoch: lock.pool_authority_epoch,
            expires_at: lock.expires_at,
            locked_at: lock.locked_at,
        };
        let intent_key = derive_dispute_bond_return_intent_key(&lock.challenge_id, &lock.lock_id);
        let intent_digest = dispute_bond_return_intent_digest(&input);
        let fenced = self
            .challenges
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::ChallengeBond,
                &intent_digest,
                None,
                false,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if fenced == FindingChallengeWriteOutcome::ExistingSame {
            let state = self
                .challenges
                .get_effect_intent(&intent_key)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .map(|record| record.state);
            if state == Some(FindingEffectIntentState::Confirmed) {
                return Ok(intent_key);
            }
        }
        self.challenges
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let instruction = FindingRailInstruction {
            idempotency_key: intent_key.clone(),
            payer: lock.pool_principal_id.clone(),
            amount_units: lock.amount_units,
            currency: lock.currency.clone(),
            pool_principal_id: lock.pool_principal_id.clone(),
            rail_destination: lock.owner_hex.clone(),
        };
        let instruction_digest = canonical_digest_of(&instruction)?;
        match self.rail.dispatch(&instruction) {
            Ok(observation)
                if rail_observation_matches(&instruction, &instruction_digest, &observation) =>
            {
                self.challenges
                    .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(intent_key)
            }
            Ok(_) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::DisputeBondRail(
                    "return observation does not reconcile to the dispatched instruction"
                        .to_owned(),
                ))
            }
            Err(reason) => {
                let _ = self.challenges.advance_effect_intent(
                    &intent_key,
                    FindingEffectIntentState::Failed,
                    now,
                );
                Err(ChallengeCoordinatorError::DisputeBondRail(reason))
            }
        }
    }
}
