// Effect intents, root bindings, impairment reconciliation, transitions.

impl SqliteFindingChallengeStore {
    /// Fence one semantic effect before anything is dispatched for it.
    ///
    /// `intent_key` is the domain-separated semantic key and
    /// `intent_digest` the canonical commitment to what that effect does.
    /// An identical retry reconciles to the same row and reports
    /// [`FindingChallengeWriteOutcome::ExistingSame`], so a resumed worker
    /// never fences twice. A different commitment under a key that is
    /// already durable is a conflicting disposition of one effect, and it
    /// rejects rather than rewriting what a dispatch may already have
    /// acted on.
    pub fn record_effect_intent(
        &self,
        intent_key: &str,
        kind: FindingEffectIntentKind,
        intent_digest: &str,
        liability_key: Option<&str>,
        settlement_required: bool,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(intent_key, "intent_key")?;
        require_hex64(intent_digest, "intent_digest")?;
        if let Some(key) = liability_key {
            require_hex64(key, "liability_key")?;
        }
        if settlement_required && liability_key.is_none() {
            return Err(invariant(
                "a settlement-required effect must name its liability",
            ));
        }
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_effect_intent_tx(&transaction, intent_key)? {
            if existing.kind == kind
                && existing.intent_digest == intent_digest
                && existing.liability_key.as_deref() == liability_key
                && existing.settlement_required == settlement_required
            {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "conflicting effect intent under an existing intent key".to_owned(),
            ));
        }
        if let Some(key) = liability_key {
            if load_liability_tx(&transaction, key)?.is_none() {
                return Err(FindingChallengeStoreError::NotFound);
            }
        }
        let recorded_at = sqlite_i64(now, "now")?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO effect_intents (
                    intent_key, liability_key, kind, intent_digest,
                    settlement_required, state, attempt_count, recorded_at,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6)
                "#,
                params![
                    intent_key,
                    liability_key,
                    effect_intent_kind_name(kind),
                    intent_digest,
                    i64::from(settlement_required),
                    recorded_at,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("effect intent insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }
    /// Refine a root intent with the exact proof values published and passed
    /// to the vault. The first binding is immutable. A failed seller retry
    /// appends a chained refresh while retaining every earlier binding.
    pub fn bind_effect_root(
        &self,
        intent_key: &str,
        liability_key: &str,
        merkle_root: &str,
        evidence_hash: &str,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(intent_key, "intent_key")?;
        require_hex64(liability_key, "liability_key")?;
        require_chain_hash(merkle_root, "merkle_root")?;
        require_chain_hash(evidence_hash, "evidence_hash")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let intent = load_effect_intent_tx(&transaction, intent_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if let Some(existing) = load_effect_root_binding_tx(&transaction, intent_key)? {
            if existing.liability_key == liability_key
                && existing.merkle_root == merkle_root
                && existing.evidence_hash == evidence_hash
            {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            if try_append_effect_root_refresh(
                &transaction,
                &intent,
                &existing,
                intent_key,
                liability_key,
                merkle_root,
                evidence_hash,
                now,
            )? {
                self.commit_write(transaction)?;
                self.sync_after_write(&connection)?;
                return Ok(FindingChallengeWriteOutcome::Inserted);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "root intent is already bound to a different anchor proof".to_owned(),
            ));
        }
        if intent.kind != FindingEffectIntentKind::RootIntent
            || intent.liability_key.as_deref() != Some(liability_key)
            || intent.state != FindingEffectIntentState::Pending
            || intent.attempt_count != 0
        {
            return Err(FindingChallengeStoreError::Conflict(
                "only an undispatched pending root intent can bind an anchor proof".to_owned(),
            ));
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO effect_root_bindings (
                    intent_key, liability_key, merkle_root, evidence_hash, bound_at
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    intent_key,
                    liability_key,
                    merkle_root,
                    evidence_hash,
                    sqlite_i64(now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "effect root binding insert did not affect one row",
            ));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Confirm publication of the exact proof bound to one root intent.
    /// The observed root and evidence hash are required again at the
    /// terminal transition so a caller cannot confirm a different root
    /// through the generic effect lifecycle.
    pub fn confirm_effect_root(
        &self,
        intent_key: &str,
        merkle_root: &str,
        evidence_hash: &str,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(intent_key, "intent_key")?;
        require_chain_hash(merkle_root, "merkle_root")?;
        require_chain_hash(evidence_hash, "evidence_hash")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let intent = load_effect_intent_tx(&transaction, intent_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        let binding = load_effect_root_binding_tx(&transaction, intent_key)?.ok_or_else(|| {
            FindingChallengeStoreError::Conflict(
                "root intent has no exact anchor-proof binding".to_owned(),
            )
        })?;
        if intent.kind != FindingEffectIntentKind::RootIntent
            || binding.merkle_root != merkle_root
            || binding.evidence_hash != evidence_hash
        {
            return Err(FindingChallengeStoreError::Conflict(
                "root confirmation does not match its exact anchor-proof binding".to_owned(),
            ));
        }
        if intent.state == FindingEffectIntentState::Confirmed {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        if intent.state != FindingEffectIntentState::Dispatched {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "root intent cannot confirm from {}",
                effect_intent_state_name(intent.state)
            )));
        }
        let changed = transaction
            .execute(
                r#"
                UPDATE effect_intents SET state = 'confirmed', updated_at = ?2
                WHERE intent_key = ?1 AND state = 'dispatched'
                "#,
                params![intent_key, sqlite_i64(now, "now")?],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("root confirmation did not affect one intent"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Advance one effect intent along its dispatch lifecycle. Entering
    /// `dispatched` counts one attempt. Idempotent on the state already
    /// recorded; an illegal edge rejects.
    pub fn advance_effect_intent(
        &self,
        intent_key: &str,
        state: FindingEffectIntentState,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(intent_key, "intent_key")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let intent = load_effect_intent_tx(&transaction, intent_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if state == FindingEffectIntentState::Confirmed
            && (intent.kind == FindingEffectIntentKind::RootIntent
                || (intent.kind == FindingEffectIntentKind::SellerImpair
                    && intent.settlement_required))
        {
            return Err(FindingChallengeStoreError::Conflict(
                "confirmation requires the effect's authenticated reconciliation values".to_owned(),
            ));
        }
        if intent.state == state {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        if !effect_intent_edge_is_legal(intent.state, state) {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "effect intent cannot move from {} to {}",
                effect_intent_state_name(intent.state),
                effect_intent_state_name(state)
            )));
        }
        if intent.kind == FindingEffectIntentKind::RootIntent
            && state == FindingEffectIntentState::Dispatched
            && load_effect_root_binding_tx(&transaction, intent_key)?.is_none()
        {
            return Err(FindingChallengeStoreError::Conflict(
                "root intent must bind its anchor proof before dispatch".to_owned(),
            ));
        }
        if intent.kind == FindingEffectIntentKind::Retraction
            && state == FindingEffectIntentState::Dispatched
        {
            let liability_key = intent
                .liability_key
                .as_deref()
                .ok_or_else(|| invariant("a retraction intent must identify its liability"))?;
            let liability = load_liability_tx(&transaction, liability_key)?
                .ok_or(FindingChallengeStoreError::NotFound)?;
            let confirmed_impairments: i64 = transaction
                .query_row(
                    r#"
                    SELECT COUNT(*) FROM effect_intents
                    WHERE liability_key = ?1
                      AND kind = 'seller_impair'
                      AND settlement_required = 1
                      AND state = 'confirmed'
                    "#,
                    [liability_key],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if confirmed_impairments != 1 || liability.quarantined {
                return Err(FindingChallengeStoreError::Conflict(
                    "retraction dispatch requires one confirmed, reconciled seller impairment"
                        .to_owned(),
                ));
            }
        }
        let attempts = if state == FindingEffectIntentState::Dispatched {
            intent
                .attempt_count
                .checked_add(1)
                .ok_or_else(|| invariant("effect intent attempts overflowed u64"))?
        } else {
            intent.attempt_count
        };
        let changed = transaction
            .execute(
                r#"
                UPDATE effect_intents
                SET state = ?3, attempt_count = ?4, updated_at = ?5
                WHERE intent_key = ?1 AND state = ?2
                "#,
                params![
                    intent_key,
                    effect_intent_state_name(intent.state),
                    effect_intent_state_name(state),
                    sqlite_i64(attempts, "attempt_count")?,
                    sqlite_i64(now, "now")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("effect intent transition did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Confirm a settlement-required seller impairment only with the opaque
    /// evidence emitted by the settlement reconciliation choke point.
    ///
    /// The generic lifecycle deliberately cannot express this transition,
    /// and this surface accepts no caller-authored transaction hash. The
    /// exact reconciliation digest and transaction are retained atomically
    /// with confirmation for restart recovery and rollback protection.
    pub fn confirm_reconciled_seller_impairment(
        &self,
        reconciliation: &ConfirmedFindingImpairmentReconciliation,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.confirm_seller_impairment_with_evidence(
            &SellerImpairmentReconciliationEvidence {
                intent_key: reconciliation.intent_id(),
                liability_key: reconciliation.liability_key(),
                tx_hash: reconciliation.tx_hash(),
                reconciliation_sha256: reconciliation.reconciliation_sha256(),
            },
            false,
            now,
        )
    }

    /// Exact authenticated reconciliation retained for one seller
    /// impairment intent.
    pub fn get_seller_impairment_reconciliation(
        &self,
        intent_key: &str,
    ) -> Result<Option<FindingSellerImpairmentReconciliationRecord>, FindingChallengeStoreError>
    {
        require_hex64(intent_key, "intent_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_seller_impairment_reconciliation_tx(&transaction, intent_key)
    }

    /// Confirm one seller impairment and quarantine its liability in the
    /// same write transaction.
    ///
    /// This is the fail-closed terminal for a transaction that was proved
    /// to match its intent but whose post-dispatch chain observation no
    /// longer matches the signed snapshot. Publishing the confirmed intent
    /// without the quarantine would create a window in which another
    /// finalizer could settle the liability from stale state.
    pub fn confirm_seller_impairment_and_quarantine(
        &self,
        reconciliation: &ConfirmedFindingImpairmentReconciliation,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.confirm_seller_impairment_with_evidence(
            &SellerImpairmentReconciliationEvidence {
                intent_key: reconciliation.intent_id(),
                liability_key: reconciliation.liability_key(),
                tx_hash: reconciliation.tx_hash(),
                reconciliation_sha256: reconciliation.reconciliation_sha256(),
            },
            true,
            now,
        )
    }

    /// Validate the current observation against the exact reconciliation
    /// retained with a confirmed seller impairment, then clear quarantine in
    /// the same write transaction. A mismatched reobservation leaves the
    /// liability quarantined.
    pub fn reconcile_seller_impairment_quarantine(
        &self,
        reconciliation: &ConfirmedFindingImpairmentReconciliation,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.reconcile_seller_impairment_quarantine_with_evidence(
            &SellerImpairmentReconciliationEvidence {
                intent_key: reconciliation.intent_id(),
                liability_key: reconciliation.liability_key(),
                tx_hash: reconciliation.tx_hash(),
                reconciliation_sha256: reconciliation.reconciliation_sha256(),
            },
            now,
        )
    }

    fn reconcile_seller_impairment_quarantine_with_evidence(
        &self,
        evidence: &SellerImpairmentReconciliationEvidence<'_>,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(evidence.intent_key, "intent_key")?;
        require_hex64(evidence.liability_key, "liability_key")?;
        require_chain_hash(evidence.tx_hash, "reconciliation.tx_hash")?;
        require_hex64(
            evidence.reconciliation_sha256,
            "reconciliation.reconciliation_sha256",
        )?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let intent = load_effect_intent_tx(&transaction, evidence.intent_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        let retained = load_seller_impairment_reconciliation_tx(&transaction, evidence.intent_key)?
            .ok_or_else(|| {
                invariant("confirmed seller impairment has no retained reconciliation")
            })?;
        if intent.kind != FindingEffectIntentKind::SellerImpair
            || intent.state != FindingEffectIntentState::Confirmed
            || !intent.settlement_required
            || intent.liability_key.as_deref() != Some(evidence.liability_key)
            || retained.liability_key != evidence.liability_key
            || retained.intent_digest != intent.intent_digest
            || retained.tx_hash != evidence.tx_hash
            || retained.reconciliation_sha256 != evidence.reconciliation_sha256
        {
            return Err(FindingChallengeStoreError::Conflict(
                "reobserved seller impairment does not match its retained reconciliation"
                    .to_owned(),
            ));
        }
        let liability = load_liability_tx(&transaction, evidence.liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.state != FindingLiabilityState::Finalizing {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "liability is in state {}, not the expected finalizing",
                liability_state_name(liability.state)
            )));
        }
        if !liability.quarantined {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE liability_heads
                SET quarantined = 0, updated_at = ?2
                WHERE liability_key = ?1 AND state = 'finalizing' AND quarantined = 1
                "#,
                params![evidence.liability_key, sqlite_i64(now, "now")?],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(invariant("liability quarantine did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    fn confirm_seller_impairment_with_evidence(
        &self,
        evidence: &SellerImpairmentReconciliationEvidence<'_>,
        quarantine: bool,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(evidence.intent_key, "intent_key")?;
        require_hex64(evidence.liability_key, "liability_key")?;
        require_chain_hash(evidence.tx_hash, "reconciliation.tx_hash")?;
        require_hex64(
            evidence.reconciliation_sha256,
            "reconciliation.reconciliation_sha256",
        )?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let intent = load_effect_intent_tx(&transaction, evidence.intent_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if intent.kind != FindingEffectIntentKind::SellerImpair
            || !intent.settlement_required
            || intent.liability_key.as_deref() != Some(evidence.liability_key)
        {
            return Err(FindingChallengeStoreError::Conflict(
                "seller impairment confirmation does not match its reconciled intent".to_owned(),
            ));
        }
        let liability = load_liability_tx(&transaction, evidence.liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.state != FindingLiabilityState::Finalizing {
            return Err(FindingChallengeStoreError::Conflict(format!(
                "liability is in state {}, not the expected finalizing",
                liability_state_name(liability.state)
            )));
        }

        let mut changed = false;
        match intent.state {
            FindingEffectIntentState::Confirmed => {
                let retained =
                    load_seller_impairment_reconciliation_tx(&transaction, evidence.intent_key)?
                        .ok_or_else(|| {
                            invariant("confirmed seller impairment has no retained reconciliation")
                        })?;
                if retained.liability_key != evidence.liability_key
                    || retained.intent_digest != intent.intent_digest
                    || retained.tx_hash != evidence.tx_hash
                    || retained.reconciliation_sha256 != evidence.reconciliation_sha256
                {
                    return Err(FindingChallengeStoreError::Conflict(
                        "seller impairment is already bound to another reconciliation".to_owned(),
                    ));
                }
            }
            FindingEffectIntentState::Dispatched => {
                let inserted = transaction
                    .execute(
                        r#"
                        INSERT INTO finding_seller_impairment_reconciliations (
                            intent_key, liability_key, intent_digest, tx_hash,
                            reconciliation_sha256, recorded_at
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                        "#,
                        params![
                            evidence.intent_key,
                            evidence.liability_key,
                            intent.intent_digest,
                            evidence.tx_hash,
                            evidence.reconciliation_sha256,
                            sqlite_i64(now, "now")?,
                        ],
                    )
                    .map_err(sqlite_error)?;
                if inserted != 1 {
                    return Err(invariant(
                        "seller impairment reconciliation insert did not affect one row",
                    ));
                }
                let updated = transaction
                    .execute(
                        r#"
                        UPDATE effect_intents SET state = 'confirmed', updated_at = ?2
                        WHERE intent_key = ?1 AND state = 'dispatched'
                        "#,
                        params![evidence.intent_key, sqlite_i64(now, "now")?],
                    )
                    .map_err(sqlite_error)?;
                if updated != 1 {
                    return Err(invariant(
                        "seller impairment confirmation did not affect one intent",
                    ));
                }
                changed = true;
            }
            state => {
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "seller impairment cannot confirm from {}",
                    effect_intent_state_name(state)
                )));
            }
        }
        if quarantine && !liability.quarantined {
            let updated = transaction
                .execute(
                    r#"
                    UPDATE liability_heads
                    SET quarantined = 1, updated_at = ?2
                    WHERE liability_key = ?1 AND state = 'finalizing' AND quarantined = 0
                    "#,
                    params![evidence.liability_key, sqlite_i64(now, "now")?],
                )
                .map_err(sqlite_error)?;
            if updated != 1 {
                return Err(invariant("liability quarantine did not affect one row"));
            }
            changed = true;
        }
        if !changed {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    #[cfg(test)]
    fn confirm_reconciled_seller_impairment_for_tests(
        &self,
        intent_key: &str,
        liability_key: &str,
        intent_digest: &str,
        tx_hash: &str,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        let reconciliation_sha256 = sha256_hex(
            format!(
                "chio.finding.test-impairment-reconciliation.v1\0{intent_key}\0{liability_key}\0{intent_digest}\0{tx_hash}"
            )
            .as_bytes(),
        );
        self.confirm_seller_impairment_with_evidence(
            &SellerImpairmentReconciliationEvidence {
                intent_key,
                liability_key,
                tx_hash,
                reconciliation_sha256: &reconciliation_sha256,
            },
            false,
            now,
        )
    }

    #[cfg(test)]
    fn confirm_seller_impairment_and_quarantine_for_tests(
        &self,
        intent_key: &str,
        liability_key: &str,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        let tx_hash = format!("0x{}", sha256_hex(intent_key.as_bytes()));
        let reconciliation_sha256 = sha256_hex(
            format!(
                "chio.finding.test-impairment-quarantine.v1\0{intent_key}\0{liability_key}\0{tx_hash}"
            )
            .as_bytes(),
        );
        self.confirm_seller_impairment_with_evidence(
            &SellerImpairmentReconciliationEvidence {
                intent_key,
                liability_key,
                tx_hash: &tx_hash,
                reconciliation_sha256: &reconciliation_sha256,
            },
            true,
            now,
        )
    }

    #[cfg(test)]
    fn reconcile_seller_impairment_quarantine_for_tests(
        &self,
        intent_key: &str,
        liability_key: &str,
        tx_hash: &str,
        reconciliation_sha256: &str,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        self.reconcile_seller_impairment_quarantine_with_evidence(
            &SellerImpairmentReconciliationEvidence {
                intent_key,
                liability_key,
                tx_hash,
                reconciliation_sha256,
            },
            now,
        )
    }

    /// One effect intent by its domain-separated key.
    pub fn get_effect_intent(
        &self,
        intent_key: &str,
    ) -> Result<Option<FindingEffectIntentRecord>, FindingChallengeStoreError> {
        require_hex64(intent_key, "intent_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_effect_intent_tx(&transaction, intent_key)
    }

    /// The immutable anchor-proof binding for one root effect intent.
    pub fn get_effect_root_binding(
        &self,
        intent_key: &str,
    ) -> Result<Option<FindingEffectRootBindingRecord>, FindingChallengeStoreError> {
        require_hex64(intent_key, "intent_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_effect_root_binding_tx(&transaction, intent_key)
    }

    /// Every effect intent fenced for one liability, oldest first.
    pub fn list_effect_intents(
        &self,
        liability_key: &str,
    ) -> Result<Vec<FindingEffectIntentRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(&format!(
                r#"
                SELECT {EFFECT_INTENT_COLUMNS} FROM effect_intents
                WHERE liability_key = ?1
                ORDER BY recorded_at ASC, intent_key ASC
                LIMIT ?2
                "#
            ))
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![liability_key, list_limit()?], map_effect_intent)
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter().map(effect_intent_from_raw).collect()
    }

    /// One liability edge, guarded twice: the caller names the state it
    /// believes the head is in, and that state must be the only legal
    /// source of this edge, so no caller can skip a state by naming a
    /// later one. Idempotent once the head already sits at the target.
    #[cfg(test)]
    fn transition_liability(
        &self,
        liability_key: &str,
        expected_state: FindingLiabilityState,
        source_state: FindingLiabilityState,
        target_state: FindingLiabilityState,
        publication_pending: Option<bool>,
        now: u64,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        require_trusted_time(now, "now")?;
        require_transition_source(expected_state, source_state, target_state)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let (outcome, _) = apply_liability_transition_tx(
            &transaction,
            liability_key,
            source_state,
            target_state,
            publication_pending,
            now,
        )?;
        if outcome == FindingChallengeWriteOutcome::ExistingSame {
            return Ok(outcome);
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }
}
