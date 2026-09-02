// Governance cases and sealed claim snapshots.

impl SqliteFindingChallengeStore {
    /// Record one governance case against a liability. A case that
    /// supersedes another stamps that predecessor superseded in the same
    /// transaction, so the index never commits a supersession only half
    /// applied. Idempotent on the case id; conflicting parameters reject,
    /// as does superseding a case that another case already superseded.
    pub fn record_governance_case(
        &self,
        input: &FindingGovernanceCaseInput<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_governance_case(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_case_tx(&transaction, input.case_id)? {
            if governance_case_matches(&existing, input) {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "case id is already bound to a different governance case".to_owned(),
            ));
        }
        let liability = load_liability_tx(&transaction, input.liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if liability.finding_id != input.finding_id || liability.listing_id != input.listing_id {
            return Err(FindingChallengeStoreError::Conflict(
                "governance case does not name the liability's finding and listing".to_owned(),
            ));
        }
        // Successful appeal supersession and the transition to
        // `finalizing` contend under the same immediate-write lock. Once
        // finalization wins that compare-and-set, a late appeal cannot
        // replace the sanction between the coordinator's finality check
        // and impairment dispatch.
        if input.case_kind == FindingGovernanceCaseKind::Appeal
            && liability.state != FindingLiabilityState::PendingAppeal
        {
            return Err(FindingChallengeStoreError::Conflict(
                "an appeal may only be recorded while the liability is pending appeal".to_owned(),
            ));
        }
        if let Some(appealed) = input.appeal_of_case_id {
            let target = load_case_tx(&transaction, appealed)?.ok_or_else(|| {
                FindingChallengeStoreError::Conflict("appealed case is not recorded".to_owned())
            })?;
            if target.liability_key != input.liability_key {
                return Err(FindingChallengeStoreError::Conflict(
                    "an appeal must target a case on the same liability".to_owned(),
                ));
            }
            if target.case_kind != FindingGovernanceCaseKind::Sanction {
                return Err(FindingChallengeStoreError::Conflict(
                    "an appeal must target a sanction".to_owned(),
                ));
            }
        }
        if let Some(superseded) = input.supersedes_case_id {
            let target = load_case_tx(&transaction, superseded)?.ok_or_else(|| {
                FindingChallengeStoreError::Conflict("superseded case is not recorded".to_owned())
            })?;
            if target.liability_key != input.liability_key {
                return Err(FindingChallengeStoreError::Conflict(
                    "a case may only supersede one on the same liability".to_owned(),
                ));
            }
            if target.superseded_by_case_id.is_some() {
                return Err(FindingChallengeStoreError::Conflict(
                    "the named case has already been superseded".to_owned(),
                ));
            }
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO governance_case_index (
                    case_id, finding_id, listing_id, liability_key, case_kind,
                    case_state, appeal_of_case_id, supersedes_case_id,
                    superseded_by_case_id, recorded_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9)
                "#,
                params![
                    input.case_id,
                    input.finding_id,
                    input.listing_id,
                    input.liability_key,
                    case_kind_name(input.case_kind),
                    input.case_state,
                    input.appeal_of_case_id,
                    input.supersedes_case_id,
                    sqlite_i64(input.recorded_at, "recorded_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("governance case insert did not affect one row"));
        }
        if let Some(superseded) = input.supersedes_case_id {
            let changed = transaction
                .execute(
                    r#"
                    UPDATE governance_case_index SET superseded_by_case_id = ?2
                    WHERE case_id = ?1 AND superseded_by_case_id IS NULL
                    "#,
                    params![superseded, input.case_id],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(invariant("case supersession did not affect one row"));
            }
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// The single live governance case on one liability: the one no other
    /// case supersedes.
    ///
    /// Fails closed on ambiguity. Two live cases targeting one defect mean
    /// the operator cannot say which sanction or appeal governs it, and a
    /// penalty evaluated against the wrong one would slash under an
    /// authority that had been superseded, so the store refuses to name a
    /// head at all rather than pick one.
    pub fn resolve_case_head(
        &self,
        liability_key: &str,
    ) -> Result<Option<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        resolve_case_head_tx(&transaction, liability_key)
    }

    /// One governance case by its id.
    pub fn get_governance_case(
        &self,
        case_id: &str,
    ) -> Result<Option<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_case_tx(&transaction, case_id)
    }

    /// Every governance case on one liability, oldest first.
    pub fn list_governance_cases(
        &self,
        liability_key: &str,
    ) -> Result<Vec<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(&format!(
                r#"
                SELECT {CASE_COLUMNS} FROM governance_case_index
                WHERE liability_key = ?1
                ORDER BY recorded_at ASC, case_id ASC
                LIMIT ?2
                "#
            ))
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![liability_key, list_limit()?], map_case)
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter().map(case_from_raw).collect()
    }

    /// Seal one liability's claim snapshot. The snapshot is written once
    /// and stamps its two commitments onto the liability head in the same
    /// transaction, so the head can never name accounting that was not
    /// sealed. The cutoff it seals must be exactly the one the upheld
    /// transaction froze.
    ///
    /// Idempotent on an identical replay; any different figure rejects.
    pub fn seal_claim_snapshot(
        &self,
        input: &FindingClaimSnapshotInput<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_claim_snapshot(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_claim_snapshot_tx(&transaction, input.liability_key)? {
            if claim_snapshot_matches(&existing, input) {
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "liability is already sealed under different claim figures".to_owned(),
            ));
        }
        let liability = load_liability_tx(&transaction, input.liability_key)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        match liability.state {
            FindingLiabilityState::UpheldPendingClaims | FindingLiabilityState::PendingAppeal => {}
            other => {
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "a claim snapshot cannot be sealed from state {}",
                    liability_state_name(other)
                )));
            }
        }
        if liability.purchase_cutoff_slot != Some(input.cutoff_slot) {
            return Err(FindingChallengeStoreError::Conflict(
                "claim snapshot does not seal the frozen purchase cutoff".to_owned(),
            ));
        }
        // The snapshot is immutable once written, so an early seal is a
        // permanent loss of standing for every claim the window still had
        // time to admit. The frozen deadline is the only authority on when
        // that window closed.
        match liability.claim_deadline {
            Some(deadline) if input.sealed_at >= deadline => {}
            _ => {
                return Err(FindingChallengeStoreError::Conflict(
                    "claim window has not closed for this liability".to_owned(),
                ));
            }
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO claim_snapshots (
                    liability_key, cutoff_slot, snapshot_digest,
                    allocation_digest, total_realized_spend_units, currency,
                    buyer_pool_units, community_fund_units, sealed_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    input.liability_key,
                    sqlite_i64(input.cutoff_slot, "cutoff_slot")?,
                    input.snapshot_digest,
                    input.allocation_digest,
                    sqlite_i64(
                        input.total_realized_spend_units,
                        "total_realized_spend_units"
                    )?,
                    input.currency,
                    sqlite_i64(input.buyer_pool_units, "buyer_pool_units")?,
                    sqlite_i64(input.community_fund_units, "community_fund_units")?,
                    sqlite_i64(input.sealed_at, "sealed_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("claim snapshot insert did not affect one row"));
        }
        let stamped = transaction
            .execute(
                r#"
                UPDATE liability_heads
                SET snapshot_digest = ?2, allocation_digest = ?3, updated_at = ?4
                WHERE liability_key = ?1 AND snapshot_digest IS NULL
                "#,
                params![
                    input.liability_key,
                    input.snapshot_digest,
                    input.allocation_digest,
                    sqlite_i64(input.sealed_at, "sealed_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if stamped != 1 {
            return Err(invariant("claim snapshot stamp did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// One liability's sealed claim snapshot.
    pub fn get_claim_snapshot(
        &self,
        liability_key: &str,
    ) -> Result<Option<FindingClaimSnapshotRecord>, FindingChallengeStoreError> {
        require_hex64(liability_key, "liability_key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_claim_snapshot_tx(&transaction, liability_key)
    }
}
