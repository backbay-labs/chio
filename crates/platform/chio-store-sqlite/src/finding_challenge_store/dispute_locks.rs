// Dispute lock reservation, bond lock and release, and filing closure.

impl SqliteFindingChallengeStore {
    /// Reserve one buyer submission's dispute-lock identity before any
    /// external funding is dispatched. The reservation is permanent and
    /// idempotent for the exact same challenge and terms; reusing either
    /// the lock id or challenge id with different terms rejects before
    /// value can move.
    pub fn reserve_dispute_lock(
        &self,
        input: &FindingDisputeLockInput<'_>,
        reserved_at: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_dispute_lock(input)?;
        require_trusted_time(reserved_at, "reserved_at")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(matches) = dispute_lock_reservation_matches(&transaction, input)? {
            return if matches {
                Ok(FindingChallengeWriteOutcome::ExistingSame)
            } else {
                Err(FindingChallengeStoreError::Conflict(
                    "challenge is already bound to a different dispute-lock reservation".to_owned(),
                ))
            };
        }
        let challenge = load_challenge_tx(&transaction, input.challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if challenge.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission {
            return Err(FindingChallengeStoreError::Conflict(
                "a venue audit posts no dispute bond".to_owned(),
            ));
        }
        if challenge.challenger_hex.as_deref() != Some(input.owner_hex) {
            return Err(FindingChallengeStoreError::Conflict(
                "dispute bond owner is not the challenger the challenge names".to_owned(),
            ));
        }
        if is_terminal_challenge_state(challenge.state) {
            return Err(FindingChallengeStoreError::Conflict(
                "a closed challenge cannot reserve a fresh dispute bond".to_owned(),
            ));
        }
        reject_bound_identifier(
            &transaction,
            "SELECT challenge_id FROM dispute_lock_reservations WHERE lock_id = ?1",
            input.lock_id,
            "dispute lock id",
        )?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO dispute_lock_reservations (
                    lock_id, challenge_id, owner_hex,
                    schedule_envelope_sha256, amount_units, currency,
                    pool_principal_id, pool_rail_destination,
                    pool_authority_epoch, expires_at, locked_at, reserved_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
                )
                "#,
                params![
                    input.lock_id,
                    input.challenge_id,
                    input.owner_hex,
                    input.schedule_envelope_sha256,
                    sqlite_i64(input.amount_units, "amount_units")?,
                    input.currency,
                    input.pool_principal_id,
                    input.pool_rail_destination,
                    sqlite_i64(input.pool_authority_epoch, "pool_authority_epoch")?,
                    sqlite_i64(input.expires_at, "expires_at")?,
                    sqlite_i64(input.locked_at, "locked_at")?,
                    sqlite_i64(reserved_at, "reserved_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "dispute lock reservation insert did not affect one row",
            ));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Lock one buyer submission's dispute bond. The bond is exclusive
    /// per challenge, is pinned to the dispute class, and must be owned by
    /// the challenger the challenge names, so a third party cannot post a
    /// bond for someone else's submission. A venue audit posts no bond and
    /// is refused here.
    ///
    /// Idempotent on the challenge: an identical replay returns
    /// [`FindingChallengeWriteOutcome::ExistingSame`] without locking
    /// again, and conflicting parameters reject.
    pub fn lock_dispute_bond(
        &self,
        input: &FindingDisputeLockInput<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_dispute_lock(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if dispute_lock_reservation_matches(&transaction, input)? != Some(true) {
            return Err(FindingChallengeStoreError::Conflict(
                "dispute bond has no exact durable lock reservation".to_owned(),
            ));
        }
        let funding_key = derive_dispute_bond_funding_intent_key(input.challenge_id, input.lock_id);
        let funding = load_effect_intent_tx(&transaction, &funding_key)?.ok_or_else(|| {
            FindingChallengeStoreError::Conflict(
                "dispute bond has no independently confirmed funding intent".to_owned(),
            )
        })?;
        if funding.kind != FindingEffectIntentKind::ChallengeBond
            || funding.liability_key.is_some()
            || funding.settlement_required
            || funding.intent_digest != dispute_bond_funding_intent_digest(input)
            || funding.state != FindingEffectIntentState::Confirmed
        {
            return Err(FindingChallengeStoreError::Conflict(
                "dispute bond funding intent is not confirmed for this lock".to_owned(),
            ));
        }
        if let Some(existing) = load_dispute_lock_tx(&transaction, input.challenge_id)? {
            if dispute_lock_matches(&existing, input) {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "challenge is already bound to a different dispute bond".to_owned(),
            ));
        }
        let challenge = load_challenge_tx(&transaction, input.challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if challenge.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission {
            return Err(FindingChallengeStoreError::Conflict(
                "a venue audit posts no dispute bond".to_owned(),
            ));
        }
        if challenge.challenger_hex.as_deref() != Some(input.owner_hex) {
            return Err(FindingChallengeStoreError::Conflict(
                "dispute bond owner is not the challenger the challenge names".to_owned(),
            ));
        }
        if is_terminal_challenge_state(challenge.state) {
            return Err(FindingChallengeStoreError::Conflict(
                "a closed challenge cannot take a fresh dispute bond".to_owned(),
            ));
        }
        reject_bound_identifier(
            &transaction,
            "SELECT challenge_id FROM dispute_locks WHERE lock_id = ?1",
            input.lock_id,
            "dispute lock id",
        )?;
        let locked_at = sqlite_i64(input.locked_at, "locked_at")?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO dispute_locks (
                    lock_id, challenge_id, owner_hex, bond_class,
                    schedule_envelope_sha256, amount_units, currency,
                    pool_principal_id, pool_rail_destination,
                    pool_authority_epoch, expires_at, state, locked_at,
                    updated_at
                ) VALUES (
                    ?1, ?2, ?3, 'dispute', ?4, ?5, ?6, ?7, ?8, ?9,
                    ?10, 'locked', ?11, ?11
                )
                "#,
                params![
                    input.lock_id,
                    input.challenge_id,
                    input.owner_hex,
                    input.schedule_envelope_sha256,
                    sqlite_i64(input.amount_units, "amount_units")?,
                    input.currency,
                    input.pool_principal_id,
                    input.pool_rail_destination,
                    sqlite_i64(input.pool_authority_epoch, "pool_authority_epoch")?,
                    sqlite_i64(input.expires_at, "expires_at")?,
                    locked_at,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("dispute lock insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Dispose one dispute bond exactly once.
    ///
    /// A bond is only disposed once its challenge is closed, and
    /// forfeiture is only available against a rejected challenge: an
    /// upheld challenge gets its bond back, and an indeterminate one never
    /// forfeits for an infrastructure or availability failure. Idempotent
    /// on the disposition already recorded; a second, different
    /// disposition rejects.
    pub fn release_dispute_bond(
        &self,
        challenge_id: &str,
        disposition: FindingDisputeLockDisposition,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let lock = load_dispute_lock_tx(&transaction, challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        match lock.state {
            FindingDisputeLockState::Locked => {}
            settled => {
                if settled == disposed_lock_state(disposition) {
                    return Ok(FindingChallengeWriteOutcome::ExistingSame);
                }
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "dispute bond was already {}",
                    dispute_lock_state_name(settled)
                )));
            }
        }
        let challenge = load_challenge_tx(&transaction, challenge_id)?
            .ok_or_else(|| invariant("dispute lock outlived its challenge"))?;
        if !is_terminal_challenge_state(challenge.state) {
            return Err(FindingChallengeStoreError::Conflict(
                "a dispute bond is disposed only once its challenge closes".to_owned(),
            ));
        }
        if disposition == FindingDisputeLockDisposition::Forfeited
            && challenge.state != FindingChallengeState::Rejected
        {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "a dispute bond cannot be forfeited against a challenge in state {}",
                challenge_state_name(challenge.state)
            )));
        }
        if disposition == FindingDisputeLockDisposition::Returned {
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
            let return_key =
                derive_dispute_bond_return_intent_key(input.challenge_id, input.lock_id);
            let returned = load_effect_intent_tx(&transaction, &return_key)?.ok_or_else(|| {
                FindingChallengeStoreError::Conflict(
                    "dispute bond has no independently confirmed return intent".to_owned(),
                )
            })?;
            if returned.kind != FindingEffectIntentKind::ChallengeBond
                || returned.liability_key.is_some()
                || returned.settlement_required
                || returned.intent_digest != dispute_bond_return_intent_digest(&input)
                || returned.state != FindingEffectIntentState::Confirmed
            {
                return Err(FindingChallengeStoreError::Conflict(
                    "dispute bond return intent is not confirmed for this lock".to_owned(),
                ));
            }
        }
        let changed = transaction
            .execute(
                r#"
                UPDATE dispute_locks SET state = ?2, updated_at = ?3
                WHERE challenge_id = ?1 AND state = 'locked'
                "#,
                params![
                    challenge_id,
                    dispute_lock_state_name(disposed_lock_state(disposition)),
                    sqlite_i64(now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("dispute bond disposition did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// The dispute bond locked for one challenge, if it posted one.
    pub fn get_dispute_lock(
        &self,
        challenge_id: &str,
    ) -> Result<Option<FindingDisputeLockRecord>, FindingChallengeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_dispute_lock_tx(&transaction, challenge_id)
    }

    /// Close a submitted buyer filing whose independently funded bond was
    /// recovered only after its signed expiry. The lock must already be
    /// reconstructed from the confirmed funding intent, so the subsequent
    /// return is fenced by the same durable identity as an ordinary close.
    ///
    /// This edge is deliberately unavailable from `evaluating`: once an
    /// adjudication has started, only its signed outcome may close it.
    pub fn close_expired_submitted_filing(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let challenge = load_challenge_tx(&transaction, challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        let lock = load_dispute_lock_tx(&transaction, challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if lock.state != FindingDisputeLockState::Locked || lock.expires_at > now {
            return Err(FindingChallengeStoreError::Conflict(
                "only an expired funded lock may close an unstarted filing".to_owned(),
            ));
        }
        match challenge.state {
            FindingChallengeState::IndeterminateClosed => {
                return Ok(FindingChallengeWriteOutcome::ExistingSame)
            }
            FindingChallengeState::Submitted => {}
            other => {
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "expired filing cannot close from state {}",
                    challenge_state_name(other)
                )))
            }
        }
        advance_challenge_state_tx(
            &transaction,
            challenge_id,
            "submitted",
            "indeterminate_closed",
            now,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Close an unstarted buyer filing after its collected fee was returned
    /// because the paired dispute bond never reached confirmed funding.
    ///
    /// Both money effects must already be durably confirmed, no lock may
    /// exist, and the bond-funding intent must remain unconfirmed. This
    /// keeps compensation and terminal closure crash-resumable without
    /// allowing a funded filing to discard its stake.
    pub fn close_compensated_unfunded_filing(
        &self,
        challenge_id: &str,
        collected_fee_intent_digest: &str,
        returned_fee_intent_digest: &str,
        bond_lock_id: &str,
        bond_funding_intent_digest: &str,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        require_hex64(collected_fee_intent_digest, "collected_fee_intent_digest")?;
        require_hex64(returned_fee_intent_digest, "returned_fee_intent_digest")?;
        require_identifier(bond_lock_id, "bond_lock_id")?;
        require_hex64(bond_funding_intent_digest, "bond_funding_intent_digest")?;
        require_trusted_time(now, "now")?;
        let collected_fee_intent_key = derive_dispute_fee_collection_intent_key(challenge_id);
        let returned_fee_intent_key = derive_dispute_fee_return_intent_key(challenge_id);
        let bond_funding_intent_key =
            derive_dispute_bond_funding_intent_key(challenge_id, bond_lock_id);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let challenge = load_challenge_tx(&transaction, challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if challenge.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission {
            return Err(FindingChallengeStoreError::Conflict(
                "a venue audit has no filing fee to compensate".to_owned(),
            ));
        }
        if load_dispute_lock_tx(&transaction, challenge_id)?.is_some() {
            return Err(FindingChallengeStoreError::Conflict(
                "a filing with a durable dispute lock is not unfunded".to_owned(),
            ));
        }
        for (key, expected_digest, label) in [
            (
                collected_fee_intent_key.as_str(),
                collected_fee_intent_digest,
                "collection",
            ),
            (
                returned_fee_intent_key.as_str(),
                returned_fee_intent_digest,
                "compensation",
            ),
        ] {
            let intent = load_effect_intent_tx(&transaction, key)?
                .ok_or(FindingChallengeStoreError::NotFound)?;
            if intent.kind != FindingEffectIntentKind::Fee
                || intent.liability_key.is_some()
                || intent.settlement_required
                || intent.intent_digest != expected_digest
                || intent.state != FindingEffectIntentState::Confirmed
            {
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "fee {} intent is not independently confirmed for this challenge",
                    label,
                )));
            }
        }
        if let Some(intent) = load_effect_intent_tx(&transaction, &bond_funding_intent_key)? {
            if intent.kind != FindingEffectIntentKind::ChallengeBond
                || intent.liability_key.is_some()
                || intent.settlement_required
                || intent.intent_digest != bond_funding_intent_digest
            {
                return Err(FindingChallengeStoreError::Conflict(
                    "bond funding intent does not bind this challenge and lock".to_owned(),
                ));
            }
            if intent.state == FindingEffectIntentState::Confirmed {
                return Err(FindingChallengeStoreError::Conflict(
                    "a confirmed dispute bond cannot close as unfunded".to_owned(),
                ));
            }
        }
        match challenge.state {
            FindingChallengeState::IndeterminateClosed => {
                return Ok(FindingChallengeWriteOutcome::ExistingSame)
            }
            FindingChallengeState::Submitted => {}
            other => {
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "compensated filing cannot close from state {}",
                    challenge_state_name(other)
                )))
            }
        }
        advance_challenge_state_tx(
            &transaction,
            challenge_id,
            "submitted",
            "indeterminate_closed",
            now,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }
}
