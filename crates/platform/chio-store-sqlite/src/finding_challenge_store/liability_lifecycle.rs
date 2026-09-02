// Liability open, uphold, appeal, finalizing, settlement, and reads.

impl SqliteFindingChallengeStore {
    /// Open one liability head. Idempotent on the liability key: a replay
    /// carrying the same defect, listing, allocation, and vault returns
    /// [`FindingChallengeWriteOutcome::ExistingSame`] without disturbing
    /// the state the head has already reached, and conflicting parameters
    /// reject. One defect on one backed listing has exactly one head, so
    /// a second corroborating challenge joins it rather than opening a
    /// second slashable liability.
    pub fn open_liability(
        &self,
        input: &FindingLiabilityInput<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_liability(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_liability_tx(&transaction, input.liability_key)? {
            if liability_matches(&existing, input) {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "liability key is already bound to a different defect or vault".to_owned(),
            ));
        }
        let opened_at = sqlite_i64(input.opened_at, "opened_at")?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO liability_heads (
                    liability_key, defect_key, finding_id, listing_id,
                    allocation_id, seller_hex, venue_id, chain_id,
                    vault_contract, vault_id,
                    state, upheld_challenge_id, purchase_cutoff_slot,
                    claim_deadline, appeal_window_opened_at, appeal_deadline,
                    appeal_terms_envelope_sha256, snapshot_digest,
                    allocation_digest, publication_pending, quarantined,
                    opened_at, updated_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    'open', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                    0, 0, ?11, ?11
                )
                "#,
                params![
                    input.liability_key,
                    input.defect_key,
                    input.finding_id,
                    input.listing_id,
                    input.allocation_id,
                    input.seller_hex,
                    input.venue_id,
                    input.chain_id,
                    input.vault_contract,
                    input.vault_id,
                    opened_at,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("liability head insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// The first upheld transaction: compare-and-set the liability head
    /// from `open` to `upheld_pending_claims`, record the challenge that
    /// carried it there, freeze the purchase cutoff, and block new
    /// pending-purchase slots on the listing, all in one immediate
    /// transaction on the connection the purchase store shares.
    ///
    /// The block and the frozen cutoff commit together or not at all,
    /// which is what makes the cutoff meaningful: a reserve racing this
    /// transaction either takes its slot before the block lands, and so
    /// sits at or below the cutoff the caller froze, or sees the block and
    /// is refused. No slot can appear above the cutoff and below the
    /// block.
    ///
    /// Only an upheld challenge on this liability's own finding and
    /// listing may carry it, and the cutoff must cover every slot the
    /// listing has already handed out, so no buyer who paid before the
    /// block can fall above the claim line. Idempotent on the exact
    /// challenge and cutoff already frozen; a different challenge or a
    /// different cutoff rejects.
    ///
    /// `claim_deadline` freezes with the cutoff and is never rewritten,
    /// so the window harmed buyers were promised is fixed by the first
    /// call. A replay derives its own deadline from its own clock and
    /// that value is ignored, which is what stops a retry shortening the
    /// window it is resuming.
    pub fn uphold_liability(
        &self,
        liability_key: &str,
        challenge_id: &str,
        cutoff_slot: u64,
        claim_deadline: u64,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.uphold_liability_inner(
            liability_key,
            challenge_id,
            cutoff_slot,
            claim_deadline,
            None,
            now,
        )
    }

    /// Freeze and block exactly like [`Self::uphold_liability`], while
    /// atomically requiring the authoritative allocation exposure to
    /// equal the evaluator-signed calculation. A reservation racing the
    /// coordinator's earlier read therefore lands wholly before this
    /// check and rejects the transition, or wholly after the sales block
    /// and is refused by the purchase store.
    pub fn uphold_liability_with_exposure_fence(
        &self,
        liability_key: &str,
        challenge_id: &str,
        cutoff_slot: u64,
        claim_deadline: u64,
        expected_open_exposure_units: u64,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.uphold_liability_inner(
            liability_key,
            challenge_id,
            cutoff_slot,
            claim_deadline,
            Some(expected_open_exposure_units),
            now,
        )
    }

    fn uphold_liability_inner(
        &self,
        liability_key: &str,
        challenge_id: &str,
        cutoff_slot: u64,
        claim_deadline: u64,
        expected_open_exposure_units: Option<u64>,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_identifier(challenge_id, "challenge_id")?;
        require_trusted_time(now, "now")?;
        require_trusted_time(claim_deadline, "claim_deadline")?;
        if claim_deadline <= now {
            return Err(FindingChallengeStoreError::Conflict(
                "claim deadline has already lapsed at the upheld transaction".to_owned(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(expected) = expected_open_exposure_units {
            let liability = load_liability_tx(&transaction, liability_key)?
                .ok_or(FindingChallengeStoreError::NotFound)?;
            if liability.state == FindingLiabilityState::Open {
                let authoritative =
                    outstanding_exposure_total_tx(&transaction, &liability.allocation_id, now)
                        .map_err(purchase_error)?;
                if authoritative != expected {
                    return Err(FindingChallengeStoreError::Conflict(
                        "allocation exposure changed before the upheld transaction".to_owned(),
                    ));
                }
            }
        }
        let outcome = uphold_liability_tx(
            &transaction,
            liability_key,
            challenge_id,
            cutoff_slot,
            claim_deadline,
            now,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Compare-and-set `upheld_pending_claims -> pending_appeal`, freezing
    /// the seller-signed appeal window in the same transaction.
    ///
    /// The caller supplies the already verified signed duration and the
    /// digest of the terms envelope that carried it. The store derives the
    /// absolute deadline from the trusted transition clock. A replay must
    /// present the same duration and envelope digest, and never recomputes
    /// the absolute deadline from its later clock.
    pub fn begin_appeal_window(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        appeal_terms_envelope_sha256: &str,
        appeal_window_secs: u64,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_hex64(appeal_terms_envelope_sha256, "appeal_terms_envelope_sha256")?;
        require_trusted_time(now, "now")?;
        if appeal_window_secs == 0 {
            return Err(invariant("appeal_window_secs must be nonzero"));
        }
        require_transition_source(
            expected_state,
            FindingLiabilityState::UpheldPendingClaims,
            FindingLiabilityState::PendingAppeal,
        )?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let liability = load_liability_tx(&transaction, liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.state == FindingLiabilityState::PendingAppeal {
            let same_window = liability
                .appeal_window_opened_at
                .and_then(|opened_at| opened_at.checked_add(appeal_window_secs))
                == liability.appeal_deadline;
            if same_window
                && liability.appeal_terms_envelope_sha256.as_deref()
                    == Some(appeal_terms_envelope_sha256)
            {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "appeal window is already bound to different signed terms".to_owned(),
            ));
        }
        if liability.state != FindingLiabilityState::UpheldPendingClaims {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "liability is in state {}, not the expected upheld_pending_claims",
                liability_state_name(liability.state)
            )));
        }
        let appeal_deadline = now
            .checked_add(appeal_window_secs)
            .ok_or_else(|| invariant("appeal deadline overflowed u64"))?;
        let changed = transaction
            .execute(
                r#"
                UPDATE liability_heads
                SET state = 'pending_appeal', appeal_window_opened_at = ?2,
                    appeal_deadline = ?3, appeal_terms_envelope_sha256 = ?4,
                    updated_at = ?2
                WHERE liability_key = ?1 AND state = 'upheld_pending_claims'
                "#,
                params![
                    liability_key,
                    sqlite_i64(now, "now")?,
                    sqlite_i64(appeal_deadline, "appeal_deadline")?,
                    appeal_terms_envelope_sha256,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("appeal-window transition did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Test-only raw lifecycle edge. Production finalization must use
    /// [`Self::begin_finalizing_under_sanction`] so the case head and the
    /// liability state are serialized in one transaction.
    #[cfg(test)]
    pub fn begin_finalizing(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.transition_liability(
            liability_key,
            expected_state,
            FindingLiabilityState::PendingAppeal,
            FindingLiabilityState::Finalizing,
            Some(true),
            now,
        )
    }

    /// Compare-and-set `pending_appeal -> finalizing` only while the named
    /// sanction is still the exact live governance case.
    ///
    /// This check and the state transition share one immediate
    /// transaction with appeal recording. Whichever write wins decides
    /// the outcome: a successful appeal that supersedes the sanction makes
    /// this edge refuse, while a finalizing edge that lands first makes a
    /// later appeal refuse because the liability is no longer pending
    /// appeal. Neither ordering can strand a successful appeal behind a
    /// finalizing head.
    #[cfg(test)]
    pub(crate) fn begin_finalizing_under_sanction(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        sanction_case_id: &str,
        authorization: &FindingFinalizingAuthorizationInput<'_>,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let outcome = begin_finalizing_under_sanction_tx(
            &transaction,
            liability_key,
            expected_state,
            sanction_case_id,
            authorization,
            now,
        )?;
        if outcome == FindingChallengeWriteOutcome::ExistingSame {
            return Ok(outcome);
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Exact retained authorization for one finalizing liability.
    pub fn get_finalizing_authorization(
        &self,
        liability_key: &str,
    ) -> Result<Option<FindingFinalizingAuthorizationRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        transaction
            .query_row(
                r#"
                SELECT authorization_json, authorization_sha256, recorded_at
                FROM (
                    SELECT authorization_json, authorization_sha256,
                           recorded_at, 0 AS refresh_ordinal
                    FROM finding_finalizing_authorizations
                    WHERE liability_key = ?1
                    UNION ALL
                    SELECT authorization_json, authorization_sha256,
                           recorded_at, refresh_ordinal
                    FROM finding_finalizing_authorization_refreshes
                    WHERE liability_key = ?1
                )
                ORDER BY refresh_ordinal DESC
                LIMIT 1
                "#,
                [liability_key],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?
            .map(|(authorization_json, authorization_sha256, recorded_at)| {
                Ok(FindingFinalizingAuthorizationRecord {
                    liability_key: liability_key.to_owned(),
                    authorization_json,
                    authorization_sha256,
                    recorded_at: stored_u64(recorded_at, "finalizing authorization recorded_at")?,
                })
            })
            .transpose()
    }

    /// Append a refreshed finalizing authorization before dispatch or after
    /// a retryable dispatch returned the exact seller intent to `failed`.
    ///
    /// The previous digest is a compare-and-set boundary. This prevents two
    /// observers from replacing one another's snapshot, while the append-only
    /// row keeps the entire signed authorization lineage recoverable.
    pub fn refresh_finalizing_authorization(
        &self,
        expected_previous_sha256: &str,
        authorization: &FindingFinalizingAuthorizationInput<'_>,
        expected_seller_intent: &FindingEffectIntentRecord,
        expected_root_intent: &FindingEffectIntentRecord,
        expected_root_binding: Option<&FindingEffectRootBindingRecord>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(expected_previous_sha256, "expected_previous_sha256")?;
        require_finalizing_authorization(authorization)?;
        require_hex64(&expected_seller_intent.intent_key, "seller_intent_key")?;
        require_hex64(&expected_root_intent.intent_key, "root_intent_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let liability = load_liability_tx(&transaction, authorization.liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.state != FindingLiabilityState::Finalizing {
            return Err(FindingChallengeStoreError::Conflict(
                "only a finalizing liability can refresh its authorization".to_owned(),
            ));
        }
        let seller_intent =
            load_effect_intent_tx(&transaction, &expected_seller_intent.intent_key)?
                .ok_or(FindingChallengeStoreError::NotFound)?;
        let root_intent = load_effect_intent_tx(&transaction, &expected_root_intent.intent_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        let root_binding =
            load_effect_root_binding_tx(&transaction, &expected_root_intent.intent_key)?;
        if &seller_intent != expected_seller_intent
            || &root_intent != expected_root_intent
            || root_binding.as_ref() != expected_root_binding
        {
            return Err(FindingChallengeStoreError::Conflict(
                "finalizing authorization refresh lost its effect-state fence".to_owned(),
            ));
        }
        let same_liability = Some(authorization.liability_key);
        let refreshable = seller_intent.kind == FindingEffectIntentKind::SellerImpair
            && seller_intent.liability_key.as_deref() == same_liability
            && seller_intent.settlement_required
            && root_intent.kind == FindingEffectIntentKind::RootIntent
            && root_intent.liability_key.as_deref() == same_liability
            && root_intent.settlement_required
            && match seller_intent.state {
                FindingEffectIntentState::Pending => {
                    root_intent.state == FindingEffectIntentState::Pending
                        && root_intent.attempt_count == 0
                        && root_binding.is_none()
                }
                FindingEffectIntentState::Failed => {
                    root_intent.state == FindingEffectIntentState::Confirmed
                        && root_binding.is_some()
                }
                FindingEffectIntentState::Dispatched
                | FindingEffectIntentState::Confirmed
                | FindingEffectIntentState::Quarantined => false,
            };
        if !refreshable {
            return Err(FindingChallengeStoreError::Conflict(
                "finalizing authorization may refresh only before anchor binding or during an authenticated retry"
                    .to_owned(),
            ));
        }
        let base = transaction
            .query_row(
                r#"
                SELECT authorization_json, authorization_sha256, recorded_at
                FROM finding_finalizing_authorizations
                WHERE liability_key = ?1
                "#,
                [authorization.liability_key],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| invariant("finalizing liability has no retained authorization"))?;
        let latest = transaction
            .query_row(
                r#"
                SELECT refresh_ordinal, authorization_json,
                       authorization_sha256, recorded_at
                FROM finding_finalizing_authorization_refreshes
                WHERE liability_key = ?1
                ORDER BY refresh_ordinal DESC
                LIMIT 1
                "#,
                [authorization.liability_key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let (latest_ordinal, latest_json, latest_sha256, latest_recorded_at) =
            latest.unwrap_or((0, base.0, base.1, base.2));
        if latest_sha256 == authorization.authorization_sha256 {
            if latest_json == authorization.authorization_json
                && stored_u64(latest_recorded_at, "finalizing authorization recorded_at")?
                    == authorization.recorded_at
            {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "finalizing authorization digest is already bound to different bytes".to_owned(),
            ));
        }
        if latest_sha256 != expected_previous_sha256 {
            return Err(FindingChallengeStoreError::Conflict(
                "finalizing authorization refresh lost its compare-and-set race".to_owned(),
            ));
        }
        let latest_recorded_at =
            stored_u64(latest_recorded_at, "finalizing authorization recorded_at")?;
        if authorization.recorded_at <= latest_recorded_at {
            return Err(FindingChallengeStoreError::Conflict(
                "finalizing authorization refresh time must advance".to_owned(),
            ));
        }
        let next_ordinal = latest_ordinal
            .checked_add(1)
            .ok_or_else(|| invariant("finalizing authorization refresh ordinal overflowed"))?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO finding_finalizing_authorization_refreshes (
                    liability_key, refresh_ordinal,
                    previous_authorization_sha256, authorization_json,
                    authorization_sha256, recorded_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    authorization.liability_key,
                    next_ordinal,
                    expected_previous_sha256,
                    authorization.authorization_json,
                    authorization.authorization_sha256,
                    sqlite_i64(authorization.recorded_at, "recorded_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "finalizing authorization refresh insert did not affect one row",
            ));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Compare-and-set `finalizing -> settled`, clearing the pending
    /// publication only after every required effect is confirmed.
    ///
    /// The gate and the lifecycle transition share one immediate
    /// transaction. Exactly one required seller impairment, root
    /// publication, and retraction must exist for the liability, and no
    /// required effect may remain in any state other than `confirmed`.
    pub fn settle_liability(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_trusted_time(now, "now")?;
        require_transition_source(
            expected_state,
            FindingLiabilityState::Finalizing,
            FindingLiabilityState::Settled,
        )?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let liability = load_liability_tx(&transaction, liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.state == FindingLiabilityState::Settled {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        if liability.state != FindingLiabilityState::Finalizing {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "liability is in state {}, not the expected finalizing",
                liability_state_name(liability.state)
            )));
        }
        if liability.quarantined {
            return Err(FindingChallengeStoreError::Conflict(
                "a quarantined liability cannot settle".to_owned(),
            ));
        }
        let (required, seller, root, bound_root, retraction, unconfirmed): (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = transaction
            .query_row(
                r#"
                    SELECT
                        COUNT(*),
                        COALESCE(SUM(kind = 'seller_impair'), 0),
                        COALESCE(SUM(kind = 'root_intent'), 0),
                        COALESCE(SUM(
                            kind = 'root_intent' AND EXISTS(
                                SELECT 1 FROM effect_root_bindings AS bindings
                                WHERE bindings.intent_key = effect_intents.intent_key
                            )
                        ), 0),
                        COALESCE(SUM(kind = 'retraction'), 0),
                        COALESCE(SUM(state <> 'confirmed'), 0)
                    FROM effect_intents
                    WHERE liability_key = ?1 AND settlement_required = 1
                    "#,
                [liability_key],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(sqlite_error)?;
        if required < 3 || seller != 1 || root != 1 || bound_root != 1 || retraction != 1 {
            return Err(FindingChallengeStoreError::Conflict(
                "liability does not carry the required finalization effect set".to_owned(),
            ));
        }
        if unconfirmed != 0 {
            return Err(FindingChallengeStoreError::Conflict(
                "liability still has unconfirmed required effects".to_owned(),
            ));
        }
        let (outcome, _) = apply_liability_transition_tx(
            &transaction,
            liability_key,
            FindingLiabilityState::Finalizing,
            FindingLiabilityState::Settled,
            Some(false),
            now,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Compare-and-set `pending_appeal -> reversed_before_impairment`,
    /// the appeal terminal. Nothing was impaired, so the head closes
    /// without a settlement and the seller is exonerated.
    ///
    /// The exoneration reaches the sale path in the same immediate
    /// transaction: the listing's sales block is lifted alongside the
    /// compare-and-set, so no restart can observe a head that cleared its
    /// appeal while the listing it names is still barred from selling.
    /// This is the one transition that lifts a block, and it is the mirror
    /// of the upheld transaction that raised it.
    ///
    /// The lift waits on the last holder. One listing carries one block
    /// however many heads reached it, so a listing another live liability
    /// still holds stays blocked and only that head's own exoneration
    /// releases it.
    pub fn reverse_liability_before_impairment(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_trusted_time(now, "now")?;
        require_transition_source(
            expected_state,
            FindingLiabilityState::PendingAppeal,
            FindingLiabilityState::ReversedBeforeImpairment,
        )?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let (outcome, liability) = apply_liability_transition_tx(
            &transaction,
            liability_key,
            FindingLiabilityState::PendingAppeal,
            FindingLiabilityState::ReversedBeforeImpairment,
            Some(false),
            now,
        )?;
        if !listing_holds_another_liability_tx(&transaction, &liability.listing_id, liability_key)?
        {
            lift_sales_block_tx(&transaction, &liability.listing_id, now)
                .map_err(purchase_error)?;
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Flag or clear the quarantine on one liability head. A quarantined
    /// head has an effect whose disposition cannot be established; it
    /// keeps its state and keeps purchases blocked.
    pub fn set_liability_quarantine(
        &self,
        liability_key: &str,
        quarantined: bool,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let liability = load_liability_tx(&transaction, liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.quarantined == quarantined {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        if is_terminal_liability_state(liability.state) {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "a liability in terminal state {} cannot change quarantine",
                liability_state_name(liability.state)
            )));
        }
        let changed = transaction
            .execute(
                r#"
                UPDATE liability_heads SET quarantined = ?2, updated_at = ?3
                WHERE liability_key = ?1
                "#,
                params![
                    liability_key,
                    i64::from(quarantined),
                    sqlite_i64(now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("liability quarantine did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// One liability head by its key.
    pub fn get_liability(
        &self,
        liability_key: &str,
    ) -> Result<Option<FindingLiabilityRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_liability_tx(&transaction, liability_key)
    }

    /// Every liability head carrying one defect, oldest first.
    pub fn list_liabilities_for_defect(
        &self,
        defect_key: &str,
    ) -> Result<Vec<FindingLiabilityRecord>, FindingChallengeStoreError> {
        require_hex64(defect_key, "defect_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(&format!(
                r#"
                SELECT {LIABILITY_COLUMNS} FROM liability_heads
                WHERE defect_key = ?1
                ORDER BY opened_at ASC, liability_key ASC
                LIMIT ?2
                "#
            ))
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![defect_key, list_limit()?], map_liability)
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter().map(liability_from_raw).collect()
    }
}
