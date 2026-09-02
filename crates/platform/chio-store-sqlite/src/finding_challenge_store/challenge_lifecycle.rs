// Challenge submission, evaluation, verdicts, and challenge reads.

impl SqliteFindingChallengeStore {
    /// Record one submitted challenge. Idempotent on the challenge id: a
    /// replay carrying the same challenge identity returns
    /// [`FindingChallengeWriteOutcome::ExistingSame`] without disturbing
    /// the adjudication already in progress, and conflicting parameters
    /// under an existing challenge id reject. The signed challenge
    /// envelope digest is a dedup key in its own right, so a second
    /// challenge id presenting one envelope rejects rather than opening a
    /// second adjudication of the same submission.
    pub fn submit_challenge(
        &self,
        input: &FindingChallengeSubmission<'_>,
    ) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
        validate_submission(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_challenge_tx(&transaction, input.challenge_id)? {
            if challenge_matches(&existing, input) {
                let inserted = store_challenge_submission_tx(&transaction, input)?;
                if inserted {
                    self.commit_write(transaction)?;
                    self.sync_after_write(&connection)?;
                }
                return Ok(FindingChallengeWriteOutcome::ExistingSame);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "challenge id is already bound to different challenge parameters".to_owned(),
            ));
        }
        reject_bound_identifier(
            &transaction,
            "SELECT challenge_id FROM challenges WHERE challenge_envelope_sha256 = ?1",
            input.challenge_envelope_sha256,
            "challenge envelope digest",
        )?;
        let submitted_at = sqlite_i64(input.submitted_at, "submitted_at")?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO challenges (
                    challenge_id, finding_id, listing_id,
                    challenge_envelope_sha256, authorization_branch,
                    evidence_class, challenger_hex, state, retry_count,
                    retry_deadline, outcome_envelope_sha256, submitted_at,
                    updated_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'submitted', 0, NULL, NULL, ?8, ?8
                )
                "#,
                params![
                    input.challenge_id,
                    input.finding_id,
                    input.listing_id,
                    input.challenge_envelope_sha256,
                    authorization_branch_name(input.authorization_branch),
                    evidence_class_name(input.evidence_class),
                    input.challenger_hex,
                    submitted_at,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("challenge insert did not affect one row"));
        }
        if !store_challenge_submission_tx(&transaction, input)? {
            return Err(invariant(
                "new challenge did not create its retained signed envelope",
            ));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingChallengeWriteOutcome::Inserted)
    }

    /// Move one challenge into evaluation. A submitted challenge starts
    /// its first evaluation; a retryable one starts its retry, but only
    /// inside the signed window it was granted. Past that deadline the
    /// challenge closes indeterminate here rather than admitting a late
    /// evaluation, so a lapsed window can never produce a verdict.
    /// Idempotent: a challenge already evaluating is left alone.
    pub fn begin_evaluation(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<FindingChallengeEvaluationStart, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let challenge = load_challenge_tx(&transaction, challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        let (from, to, outcome) = match challenge.state {
            FindingChallengeState::Evaluating => {
                return Ok(FindingChallengeEvaluationStart::AlreadyEvaluating);
            }
            FindingChallengeState::Submitted => (
                "submitted",
                "evaluating",
                FindingChallengeEvaluationStart::Started,
            ),
            FindingChallengeState::IndeterminateRetryable => {
                let deadline = challenge
                    .retry_deadline
                    .ok_or_else(|| invariant("retryable challenge holds no retry deadline"))?;
                if now < deadline {
                    (
                        "indeterminate_retryable",
                        "evaluating",
                        FindingChallengeEvaluationStart::Started,
                    )
                } else {
                    (
                        "indeterminate_retryable",
                        "indeterminate_closed",
                        FindingChallengeEvaluationStart::RetryWindowExpired,
                    )
                }
            }
            other => {
                return Err(FindingChallengeStoreError::Conflict(format!(
                    "challenge cannot enter evaluation from state {}",
                    challenge_state_name(other)
                )));
            }
        };
        advance_challenge_state_tx(&transaction, challenge_id, from, to, now)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(outcome)
    }

    /// Close one evaluation against its authenticated signed outcome,
    /// returning the state the challenge landed in.
    ///
    /// `Upheld` and `Rejected` are terminal immediately. `Indeterminate`
    /// grants at most one retry, and only when the caller carries a signed
    /// retry deadline still in the future and the challenge has not spent
    /// its retry already; every other indeterminate result closes the
    /// challenge. An indeterminate verdict never becomes a rejection, so
    /// it can neither forfeit a bond nor reach the penalty lane.
    ///
    /// Idempotent: replaying one verdict under the same outcome digest
    /// returns the state that verdict produced; a different verdict or a
    /// different outcome digest against a closed challenge rejects.
    pub fn record_authenticated_verdict(
        &self,
        challenge_id: &str,
        signed_outcome: &SignedFindingChallengeOutcome,
        pinned_evaluator_authority: &PublicKey,
        now: u64,
    ) -> Result<FindingChallengeState, FindingChallengeStoreError> {
        let (verdict, outcome_envelope_sha256, outcome_envelope_json) =
            self.authenticate_outcome(challenge_id, signed_outcome, pinned_evaluator_authority)?;
        if verdict == FindingChallengeVerdict::Upheld {
            return Err(FindingChallengeStoreError::Conflict(
                "upheld verdicts require the atomic exposure fence".to_owned(),
            ));
        }
        self.record_verdict(
            challenge_id,
            verdict,
            &outcome_envelope_sha256,
            &outcome_envelope_json,
            now,
        )
    }

    /// Internal raw verdict transition used by this crate's storage tests.
    /// Production callers must enter through [`Self::record_authenticated_verdict`].
    pub(crate) fn record_verdict(
        &self,
        challenge_id: &str,
        verdict: FindingChallengeVerdict,
        outcome_envelope_sha256: &str,
        outcome_envelope_json: &[u8],
        now: u64,
    ) -> Result<FindingChallengeState, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        require_outcome_envelope(outcome_envelope_sha256, outcome_envelope_json)?;
        require_trusted_time(now, "now")?;
        if let FindingChallengeVerdict::Indeterminate {
            retry_deadline: Some(deadline),
        } = verdict
        {
            require_trusted_time(deadline, "retry_deadline")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if verdict == FindingChallengeVerdict::Upheld {
            if load_challenge_tx(&transaction, challenge_id)?.is_none() {
                return Err(FindingChallengeStoreError::NotFound);
            }
            return Err(FindingChallengeStoreError::Conflict(
                "upheld verdicts require the atomic exposure fence".to_owned(),
            ));
        }
        let target = record_verdict_tx(
            &transaction,
            challenge_id,
            verdict,
            outcome_envelope_sha256,
            outcome_envelope_json,
            now,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(target)
    }

    /// Atomically close an authenticated upheld evaluation only while the
    /// evaluator's signed exposure still matches the authoritative allocation,
    /// and raise the listing sales block in the same transaction.
    ///
    /// If a purchase reservation races the evaluator's earlier read, the
    /// exposure mismatch rolls back both the block and the verdict. The
    /// challenge remains evaluating and a retry can sign the refreshed
    /// calculation. Once the transaction commits, no new reservation can
    /// change the exposure behind the terminal outcome.
    pub fn record_authenticated_upheld_verdict_with_exposure_fence(
        &self,
        challenge_id: &str,
        signed_outcome: &SignedFindingChallengeOutcome,
        pinned_evaluator_authority: &PublicKey,
        allocation_id: &str,
        expected_open_exposure_units: u64,
        now: u64,
    ) -> Result<FindingChallengeState, FindingChallengeStoreError> {
        let (verdict, outcome_envelope_sha256, outcome_envelope_json) =
            self.authenticate_outcome(challenge_id, signed_outcome, pinned_evaluator_authority)?;
        if verdict != FindingChallengeVerdict::Upheld {
            return Err(FindingChallengeStoreError::Conflict(
                "the upheld exposure fence requires an upheld signed outcome".to_owned(),
            ));
        }
        let calculation = signed_outcome
            .body
            .penalty_calculation
            .as_ref()
            .ok_or_else(|| invariant("upheld signed outcome has no penalty calculation"))?;
        if signed_outcome.body.backing_allocation_id != allocation_id
            || calculation.open_per_sale_encumbrance_units != expected_open_exposure_units
        {
            return Err(FindingChallengeStoreError::Conflict(
                "signed outcome does not bind the exposure fence".to_owned(),
            ));
        }
        self.record_upheld_verdict_with_exposure_fence(
            challenge_id,
            &outcome_envelope_sha256,
            &outcome_envelope_json,
            allocation_id,
            expected_open_exposure_units,
            now,
        )
    }

    /// Internal raw upheld transition used by this crate's storage tests.
    /// Production callers must use the authenticated entrypoint above.
    pub(crate) fn record_upheld_verdict_with_exposure_fence(
        &self,
        challenge_id: &str,
        outcome_envelope_sha256: &str,
        outcome_envelope_json: &[u8],
        allocation_id: &str,
        expected_open_exposure_units: u64,
        now: u64,
    ) -> Result<FindingChallengeState, FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        require_outcome_envelope(outcome_envelope_sha256, outcome_envelope_json)?;
        require_hex64(allocation_id, "allocation_id")?;
        require_outcome_allocation_binding(outcome_envelope_json, allocation_id)?;
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let challenge = load_challenge_tx(&transaction, challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        if challenge.state == FindingChallengeState::Evaluating {
            let authoritative = outstanding_exposure_total_tx(&transaction, allocation_id, now)
                .map_err(purchase_error)?;
            if authoritative != expected_open_exposure_units {
                return Err(FindingChallengeStoreError::Conflict(
                    "allocation exposure changed before the upheld verdict".to_owned(),
                ));
            }
            block_new_slots_tx(&transaction, &challenge.listing_id, now).map_err(purchase_error)?;
        }
        let target = record_verdict_tx(
            &transaction,
            challenge_id,
            FindingChallengeVerdict::Upheld,
            outcome_envelope_sha256,
            outcome_envelope_json,
            now,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(target)
    }

    fn authenticate_outcome(
        &self,
        challenge_id: &str,
        signed_outcome: &SignedFindingChallengeOutcome,
        pinned_evaluator_authority: &PublicKey,
    ) -> Result<(FindingChallengeVerdict, String, Vec<u8>), FindingChallengeStoreError> {
        require_identifier(challenge_id, "challenge_id")?;
        verify_signed_challenge_outcome(signed_outcome, pinned_evaluator_authority).map_err(
            |_| {
                FindingChallengeStoreError::Conflict(
                    "challenge outcome is not authenticated by the pinned evaluator".to_owned(),
                )
            },
        )?;
        let challenge = self
            .get_challenge(challenge_id)?
            .ok_or(FindingChallengeStoreError::NotFound)?;
        let body = &signed_outcome.body;
        let expected_authorization = match challenge.authorization_branch {
            FindingChallengeAuthorizationBranch::BuyerSubmission => {
                ArtifactAuthorizationKind::BuyerSubmission
            }
            FindingChallengeAuthorizationBranch::VenueAudit => {
                ArtifactAuthorizationKind::VenueAudit
            }
        };
        let expected_evidence = match challenge.evidence_class {
            FindingChallengeEvidenceClass::DigestMismatch => ArtifactEvidenceKind::DigestMismatch,
            FindingChallengeEvidenceClass::EvidenceInvalid => ArtifactEvidenceKind::EvidenceInvalid,
            FindingChallengeEvidenceClass::ReplayContradiction => {
                ArtifactEvidenceKind::ReplayContradiction
            }
        };
        if body.challenge_envelope_sha256 != challenge.challenge_envelope_sha256
            || body.finding_id != challenge.finding_id
            || body.listing_id != challenge.listing_id
            || body.authorization != expected_authorization
            || body.evidence_kind != expected_evidence
        {
            return Err(FindingChallengeStoreError::Conflict(
                "signed outcome does not bind the recorded challenge".to_owned(),
            ));
        }
        let verdict = match body.verdict {
            ArtifactVerdict::Upheld => FindingChallengeVerdict::Upheld,
            ArtifactVerdict::Rejected => FindingChallengeVerdict::Rejected,
            ArtifactVerdict::Indeterminate => FindingChallengeVerdict::Indeterminate {
                retry_deadline: body.retry_deadline,
            },
        };
        let outcome_envelope_json = canonical_json_bytes(signed_outcome)
            .map_err(|_| invariant("signed challenge outcome is not canonicalizable"))?;
        let outcome_envelope_sha256 = sha256_hex(&outcome_envelope_json);
        Ok((verdict, outcome_envelope_sha256, outcome_envelope_json))
    }

    /// Raw verdict transition for cross-crate integration fixtures only.
    #[cfg(feature = "cognition-market-test-support")]
    pub fn record_test_verdict(
        &self,
        challenge_id: &str,
        verdict: FindingChallengeVerdict,
        outcome_envelope_sha256: &str,
        outcome_envelope_json: &[u8],
        now: u64,
    ) -> Result<FindingChallengeState, FindingChallengeStoreError> {
        self.record_verdict(
            challenge_id,
            verdict,
            outcome_envelope_sha256,
            outcome_envelope_json,
            now,
        )
    }

    /// Raw upheld transition for cross-crate integration fixtures only.
    #[cfg(feature = "cognition-market-test-support")]
    pub fn record_test_upheld_verdict_with_exposure_fence(
        &self,
        challenge_id: &str,
        outcome_envelope_sha256: &str,
        outcome_envelope_json: &[u8],
        allocation_id: &str,
        expected_open_exposure_units: u64,
        now: u64,
    ) -> Result<FindingChallengeState, FindingChallengeStoreError> {
        self.record_upheld_verdict_with_exposure_fence(
            challenge_id,
            outcome_envelope_sha256,
            outcome_envelope_json,
            allocation_id,
            expected_open_exposure_units,
            now,
        )
    }

    /// One challenge by its id.
    pub fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<FindingChallengeRecord>, FindingChallengeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_challenge_tx(&transaction, challenge_id)
    }

    /// Exact signed outcome retained under its envelope digest.
    pub fn get_outcome_envelope(
        &self,
        outcome_envelope_sha256: &str,
    ) -> Result<Option<FindingChallengeOutcomeRecord>, FindingChallengeStoreError> {
        require_hex64(outcome_envelope_sha256, "outcome_envelope_sha256")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let outcome = transaction
            .query_row(
                r#"
                SELECT challenge_id, outcome_envelope_sha256,
                       outcome_envelope_json, recorded_at
                FROM finding_challenge_outcomes
                WHERE outcome_envelope_sha256 = ?1
                "#,
                [outcome_envelope_sha256],
                |row| {
                    Ok(FindingChallengeOutcomeRecord {
                        challenge_id: row.get(0)?,
                        outcome_envelope_sha256: row.get(1)?,
                        outcome_envelope_json: row.get(2)?,
                        recorded_at: stored_u64(row.get(3)?, "recorded_at").map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                3,
                                rusqlite::types::Type::Integer,
                                Box::new(error),
                            )
                        })?,
                    })
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(outcome) = &outcome {
            require_outcome_envelope(
                &outcome.outcome_envelope_sha256,
                &outcome.outcome_envelope_json,
            )?;
        }
        Ok(outcome)
    }

    /// Every challenge against one finding on one listing, oldest first.
    pub fn list_challenges(
        &self,
        finding_id: &str,
        listing_id: &str,
    ) -> Result<Vec<FindingChallengeRecord>, FindingChallengeStoreError> {
        require_hex64(finding_id, "finding_id")?;
        require_identifier(listing_id, "listing_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(&format!(
                r#"
                SELECT {CHALLENGE_COLUMNS} FROM challenges
                WHERE finding_id = ?1 AND listing_id = ?2
                ORDER BY submitted_at ASC, challenge_id ASC
                LIMIT ?3
                "#
            ))
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![finding_id, listing_id, list_limit()?],
                map_challenge,
            )
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter().map(challenge_from_raw).collect()
    }
}
