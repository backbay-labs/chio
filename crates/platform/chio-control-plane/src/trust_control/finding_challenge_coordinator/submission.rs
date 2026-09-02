// Challenge submission and evaluation admission.

impl FindingChallengeCoordinator {
    /// Authenticate and durably record one challenge, charging the
    /// dispute fee and locking the dispute bond for a buyer submission.
    ///
    /// Ordering guarantee. Every pure check runs first, including the fee
    /// and bond preconditions the durable row does not carry, so a filing
    /// that cannot be authenticated writes nothing. The challenge row is
    /// then recorded before the fee, because a charge against a challenge
    /// the store never accepted would be a stranded debit with nothing to
    /// resolve it. The fee is fenced before dispatch and the bond is
    /// locked last, so a crash anywhere replays into the same durable
    /// state: the challenge replays as an existing row, the fee intent
    /// reconciles or re-dispatches from `failed`, and the lock replays as
    /// the same lock.
    ///
    /// That ordering is why the row is not evidence of a funded filing.
    /// The lock is written only once the fee has reconciled, so it is the
    /// lock that makes a buyer submission evaluable, and a filing that
    /// stopped short of it stays inert until a replay completes it.
    ///
    /// A venue audit takes none of that path. Its authorization branch has
    /// no fee, bond, forfeiture, or reward member at all, so those fields
    /// are unrepresentable on it rather than merely rejected, and this
    /// method charges and locks nothing for it. What it owes instead is
    /// the round: a bondless filing is admitted only against the published
    /// selection that drew this listing.
    pub fn submit(
        &self,
        challenge: &SignedFindingChallenge,
        raw_finding: &str,
        now: u64,
    ) -> Result<ChallengeSubmissionOutcome, ChallengeCoordinatorError> {
        let body = &challenge.body;
        // A bondless audit resolves its signer from the exact retained round.
        // This lets an in-flight round finish across configured key rotation
        // without letting the challenge select an unrelated historical key.
        // A buyer submission verifies against the challenger it names, so
        // neither branch can borrow the other's authorization.
        let audit_authority = match &body.authorization {
            FindingChallengeAuthorization::VenueAudit(audit) => {
                let round = self
                    .filings
                    .audit_round(&audit.audit_epoch_envelope_sha256)
                    .map_err(ChallengeCoordinatorError::FilingResolver)?
                    .ok_or(ChallengeCoordinatorError::UnknownAuditRound)?;
                if self.envelope_digest(&round.epoch)? != audit.audit_epoch_envelope_sha256 {
                    return Err(ChallengeCoordinatorError::AuditRoundBinding(
                        "audit_epoch_envelope_sha256",
                    ));
                }
                if challenge.signer_key != round.epoch.signer_key {
                    return Err(ChallengeCoordinatorError::AuditRoundBinding(
                        "challenge_signer",
                    ));
                }
                let historical_policy = self
                    .filings
                    .audit_policy_for_epoch(&audit.audit_epoch_envelope_sha256)
                    .map_err(ChallengeCoordinatorError::FilingResolver)?
                    .ok_or(ChallengeCoordinatorError::UnknownAuditAuthorityPolicy)?;
                self.require_live_role(&historical_policy, now, now, "historical audit")?
            }
            FindingChallengeAuthorization::BuyerSubmission(_) => self
                .pins
                .audit_authority
                .key()
                .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("audit"))?,
        };
        verify_signed_challenge(challenge, &audit_authority)
            .map_err(|error| ChallengeCoordinatorError::ChallengeEnvelope(error.to_string()))?;
        if body.filed_at > now {
            return Err(ChallengeCoordinatorError::FilingClock);
        }
        let finding = self.resolve_finding(raw_finding, body)?;
        // The closed compatibility matrix is the only gate between a
        // challenge class and the finding it targets, and it needs both.
        ensure_challenge_class_compatibility(
            body.evidence.kind(),
            finding.guarantee_class,
            finding.evidence_class,
        )
        .map_err(|error| ChallengeCoordinatorError::ClassIncompatible(error.to_string()))?;

        let challenge_envelope_sha256 = self.envelope_digest(challenge)?;
        let challenge_envelope_json =
            canonical_json_bytes(challenge).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let (branch, challenger_hex) = match &body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => (
                FindingChallengeAuthorizationBranch::BuyerSubmission,
                Some(submission.challenger.to_hex()),
            ),
            FindingChallengeAuthorization::VenueAudit(_) => {
                (FindingChallengeAuthorizationBranch::VenueAudit, None)
            }
        };
        // The durable row carries neither the money terms of a buyer
        // filing nor the round behind a bondless one, so a filing whose
        // branch cannot be authorized must be refused before anything
        // about it becomes durable. Both branches file against the
        // seller-signed market terms the challenge binds by digest: the
        // terms carry the filing window, the audit toggle, and the bond
        // limits the seller committed the listing to.
        let terms = self.resolve_market_terms(body)?;
        let prior_filing = self
            .challenges
            .get_challenge(&body.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if prior_filing.is_none() {
            self.require_filing_window(&terms.body, body.filed_at, now)?;
        }
        match &body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => {
                self.require_bond_within_terms_limits(
                    &terms.body,
                    submission,
                    finding.guarantee_class,
                )?;
            }
            FindingChallengeAuthorization::VenueAudit(_) => {
                // A seller may sign terms that never enter the audit
                // rotation; a bondless audit against those terms has no
                // authorization to stand on, whatever round drew it.
                if !terms.body.audit_eligible {
                    return Err(ChallengeCoordinatorError::AuditIneligible);
                }
            }
        }
        // Resolve the retained admission before any durable row or money
        // effect. Its pool binding governed this sale and remains the only
        // authorized destination after venue configuration rotates. An
        // exact retained filing is provisionally checked at its original
        // receipt time so an already-funded bond remains refundable after
        // key rotation; an unfunded retry is checked again at `now` below.
        let admission_validation_at = prior_filing
            .as_ref()
            .filter(|recorded| {
                recorded.challenge_envelope_sha256 == challenge_envelope_sha256
                    && recorded.finding_id == body.finding_id
                    && recorded.listing_id == body.listing_id
            })
            .map_or(now, |recorded| recorded.submitted_at);
        let admission = self.resolve_admission(body, admission_validation_at)?;
        self.require_finding_status_feed_binding(&finding, &admission)?;
        if let FindingChallengeAuthorization::VenueAudit(audit) = &body.authorization {
            self.require_audit_selection(audit, body, &admission, now)?;
        }
        let mut recovered_received_at = match &body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => self
                .confirmed_funded_submission_received_at(
                    body,
                    &challenge_envelope_sha256,
                    submission,
                    &admission.body.challenge_administration_pool,
                )?,
            FindingChallengeAuthorization::VenueAudit(_) => None,
        };
        if recovered_received_at.is_none() {
            if let FindingChallengeAuthorization::BuyerSubmission(submission) = &body.authorization
            {
                match self.recover_expired_fee_only_submission(
                    body,
                    &challenge_envelope_sha256,
                    submission,
                    &terms.body,
                    &admission.body.challenge_administration_pool,
                    now,
                )? {
                    ExpiredFeeOnlyRecovery::Compensated => {
                        return Err(ChallengeCoordinatorError::DisputeBondWindow)
                    }
                    ExpiredFeeOnlyRecovery::FundingConfirmed { received_at } => {
                        recovered_received_at = Some(received_at);
                    }
                    ExpiredFeeOnlyRecovery::Unchanged => {}
                }
            }
            let exact_audit_replay = matches!(
                &body.authorization,
                FindingChallengeAuthorization::VenueAudit(_)
            ) && admission_validation_at != now;
            if recovered_received_at.is_none() && !exact_audit_replay {
                if admission_validation_at != now {
                    self.resolve_admission(body, now)?;
                }
                self.require_filing_window(&terms.body, body.filed_at, now)?;
            }
        }
        let received_at = recovered_received_at.unwrap_or(now);
        match &body.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => {
                self.require_dispute_terms(
                    submission,
                    &admission,
                    &admission.body.challenge_administration_pool,
                    received_at,
                )?;
            }
            FindingChallengeAuthorization::VenueAudit(_) => {}
        }
        let write = self
            .challenges
            .submit_challenge(&FindingChallengeSubmission {
                challenge_id: &body.challenge_id,
                finding_id: &body.finding_id,
                listing_id: &body.listing_id,
                challenge_envelope_sha256: &challenge_envelope_sha256,
                challenge_envelope_json: &challenge_envelope_json,
                authorization_branch: branch,
                evidence_class: evidence_class_of(body.evidence.kind()),
                challenger_hex: challenger_hex.as_deref(),
                submitted_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        let FindingChallengeAuthorization::BuyerSubmission(submission) = &body.authorization else {
            return Ok(ChallengeSubmissionOutcome {
                challenge_id: body.challenge_id.clone(),
                branch,
                write,
                dispute_fee_intent_key: None,
                dispute_bond_lock_id: None,
            });
        };
        let lock = &submission.dispute_lock_ref;
        let recorded = self
            .challenges
            .get_challenge(&body.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        let pool = &admission.body.challenge_administration_pool;
        let owner_hex = recorded
            .challenger_hex
            .as_deref()
            .ok_or(ChallengeCoordinatorError::DisputeFeePayer)?;
        let lock_input = FindingDisputeLockInput {
            lock_id: &lock.lock_id,
            challenge_id: &body.challenge_id,
            owner_hex,
            schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
            amount_units: lock.amount.units,
            currency: &lock.amount.currency,
            pool_principal_id: &pool.principal_id,
            pool_rail_destination: &pool.rail_destination,
            pool_authority_epoch: pool.authority_epoch,
            expires_at: lock.expiry,
            locked_at: recorded.submitted_at,
        };
        self.challenges
            .reserve_dispute_lock(&lock_input, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let fee_intent_key = self.charge_dispute_fee(&body.challenge_id, submission, now)?;
        self.fund_dispute_bond(
            &body.challenge_id,
            submission,
            pool,
            recorded.submitted_at,
            now,
        )?;
        self.challenges
            .lock_dispute_bond(&lock_input)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if lock.expiry <= now
            && matches!(
                recorded.state,
                FindingChallengeState::Submitted | FindingChallengeState::IndeterminateClosed
            )
        {
            if recorded.state == FindingChallengeState::Submitted {
                self.challenges
                    .close_expired_submitted_filing(&body.challenge_id, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
            }
            self.dispose_dispute_bond(&body.challenge_id, now)?;
        }
        Ok(ChallengeSubmissionOutcome {
            challenge_id: body.challenge_id.clone(),
            branch,
            write,
            dispute_fee_intent_key: Some(fee_intent_key),
            dispute_bond_lock_id: Some(lock.lock_id.clone()),
        })
    }

    /// Admit one evaluation attempt against the venue clock.
    ///
    /// Evaluability is proved before the clock is consulted, so a filing
    /// that never funded itself cannot enter evaluation and cannot be
    /// moved on by a lapsed retry window either.
    ///
    /// A challenge whose signed retry window has already lapsed is closed
    /// indeterminate by the store rather than admitted, and its bond is
    /// returned here, exactly once. That path charges no second fee: the
    /// retry reuses the same challenge, fee, lock, profile, and evidence
    /// identity, so there is nothing further to collect.
    pub fn admit_evaluation(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<EvaluationAdmission, ChallengeCoordinatorError> {
        self.require_funded_filing(challenge_id, now)?;
        let start = self
            .challenges
            .begin_evaluation(challenge_id, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        match start {
            FindingChallengeEvaluationStart::Started
            | FindingChallengeEvaluationStart::AlreadyEvaluating => {
                Ok(EvaluationAdmission::Admitted)
            }
            FindingChallengeEvaluationStart::RetryWindowExpired => {
                let disposition = self.dispose_dispute_bond(challenge_id, now)?;
                Ok(EvaluationAdmission::RetryWindowClosed { disposition })
            }
        }
    }
}
