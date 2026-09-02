// Retained-admission resolution and funded-filing recovery.

impl FindingChallengeCoordinator {
    /// Resolve and verify the retained venue admission that bound the
    /// challenged backing. The allocation in the evaluator-signed outcome
    /// comes only from this artifact.
    fn resolve_admission(
        &self,
        challenge: &FindingChallenge,
        now: u64,
    ) -> Result<SignedFindingAdmission, ChallengeCoordinatorError> {
        let admission = self
            .filings
            .admission_for_backing(
                &challenge.finding_id,
                &challenge.listing_id,
                &challenge.backing_envelope_sha256,
            )
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownAdmission)?;
        if self.envelope_digest(&admission)? != challenge.venue_admission_envelope_sha256 {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "venue_admission_envelope_sha256",
            ));
        }
        let admission_digest = self.envelope_digest(&admission)?;
        let venue_policy = self
            .filings
            .venue_policy_for_admission(&admission_digest)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownAdmission)?;
        let venue_authority = self.require_live_role(
            &venue_policy,
            admission.body.issued_at,
            now,
            "historical venue",
        )?;
        verify_signed_admission(&admission, &venue_authority, &self.venue_id)
            .map_err(|error| ChallengeCoordinatorError::AdmissionEnvelope(error.to_string()))?;
        let bindings: [(&str, &str, &'static str); 6] = [
            (
                &admission.body.finding_id,
                &challenge.finding_id,
                "finding_id",
            ),
            (
                &admission.body.finding_artifact_sha256,
                &challenge.finding_artifact_sha256,
                "finding_artifact_sha256",
            ),
            (
                &admission.body.listing_id,
                &challenge.listing_id,
                "listing_id",
            ),
            (
                &admission.body.terms_envelope_sha256,
                &challenge.terms_envelope_sha256,
                "terms_envelope_sha256",
            ),
            (
                &admission.body.profile_envelope_sha256,
                &challenge.profile_envelope_sha256,
                "profile_envelope_sha256",
            ),
            (
                &admission.body.backing_envelope_sha256,
                &challenge.backing_envelope_sha256,
                "backing_envelope_sha256",
            ),
        ];
        for (admitted, challenged, label) in bindings {
            if admitted != challenged {
                return Err(ChallengeCoordinatorError::AdmissionBinding(label));
            }
        }
        Ok(admission)
    }

    /// Bind a failed-delivery terminal back to the durable reservation that
    /// produced it. A listing may be rebacked after a denial, so matching
    /// only finding and listing would let an old zero-charge terminal slash
    /// a new allocation that never backed that attempted sale.
    fn require_failed_delivery_reservation_binding(
        &self,
        challenge: &FindingChallenge,
        evidence: &FindingChallengeClassEvidence<'_>,
        admission: &SignedFindingAdmission,
    ) -> Result<(), ChallengeCoordinatorError> {
        let FindingChallengeClassEvidence::DigestMismatch(evidence) = evidence else {
            return Ok(());
        };
        let terminal = &evidence.failed_delivery.body;
        let retained = self
            .purchases
            .get_failed_delivery_record(&terminal.failed_delivery_id)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AdmissionBinding(
                "failed_delivery_reservation",
            ))?;
        let reservation = self
            .purchases
            .get_reservation(&terminal.reservation_id)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AdmissionBinding(
                "failed_delivery_reservation",
            ))?;
        let encumbrance = self
            .purchases
            .get_encumbrance(&terminal.reservation_id)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::AdmissionBinding(
                "failed_delivery_backing",
            ))?;
        if terminal.finding_id != challenge.finding_id
            || terminal.listing_id != challenge.listing_id
            || retained.reservation_id != terminal.reservation_id
            || retained.record_sha256 != self.envelope_digest(evidence.failed_delivery)?
            || terminal.accepted_bid_envelope_sha256 != reservation.bid_envelope_sha256
            || terminal.venue_admission_envelope_sha256 != reservation.admission_envelope_sha256
            || terminal.seller_backing_envelope_sha256 != admission.body.backing_envelope_sha256
            || terminal.purchase_intent_id != reservation.purchase_intent_id
            || terminal.authoritative_payment_operation_id
                != reservation.authoritative_payment_operation_id
            || terminal.buyer.to_hex() != reservation.payer_hex
            || reservation.finding_id != challenge.finding_id
            || reservation.listing_id != challenge.listing_id
            || reservation.admission_envelope_sha256 != challenge.venue_admission_envelope_sha256
            || reservation.admission_envelope_sha256 != self.envelope_digest(admission)?
            || encumbrance.allocation_id != admission.body.backing_allocation_id
        {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "failed_delivery_reservation",
            ));
        }
        Ok(())
    }

    /// Derive the only retry horizon the signed artifacts authorize. The
    /// filing horizon and terms expiry are seller signed; a buyer lock is
    /// an additional signed cap because retry can never retain that lock
    /// beyond its own expiry.
    fn derive_retry_deadline(
        &self,
        challenge: &FindingChallenge,
        terms: &SignedFindingMarketTerms,
        now: u64,
    ) -> Result<Option<u64>, ChallengeCoordinatorError> {
        let filing_deadline = terms
            .body
            .issued_at
            .checked_add(terms.body.filing_window_secs)
            .ok_or(ChallengeCoordinatorError::TermsBinding(
                "filing window end is not representable",
            ))?;
        let mut deadline = filing_deadline.min(terms.body.expires_at);
        if let FindingChallengeAuthorization::BuyerSubmission(submission) = &challenge.authorization
        {
            deadline = deadline.min(submission.dispute_lock_ref.expiry);
        }
        Ok((deadline > now).then_some(deadline))
    }

    /// Require a buyer filing to have finished paying for itself before it
    /// can be adjudicated.
    ///
    /// The challenge row is recorded before the fee is charged, so a
    /// filing whose charge failed leaves that row behind in `submitted`.
    /// The dispute lock is the last write a submission makes and it
    /// happens only after the fee has reconciled, so the lock, not the
    /// row, is what proves both money steps landed. Without it the
    /// challenge would be adjudicated with no fee collected and no stake
    /// at risk, which is exactly what makes a frivolous filing free.
    ///
    /// A venue audit has no fee, bond, or lock member at all, so it is
    /// evaluable on its authorization alone.
    fn require_funded_filing(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let challenge = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        if challenge.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission {
            return Ok(());
        }
        let lock = self
            .challenges
            .get_dispute_lock(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::FilingUnfunded)?;
        if lock.state != FindingDisputeLockState::Locked {
            return Err(ChallengeCoordinatorError::DisputeBondWindow);
        }
        if lock.expires_at <= now {
            // The signed retry horizon may be capped exactly at the lock
            // expiry. That instant authorizes closure and return, never a
            // new attempt, so let `begin_evaluation` take only its
            // RetryWindowExpired edge. Every other expired lock denies.
            let closing_retry = challenge.state == FindingChallengeState::IndeterminateRetryable
                && challenge
                    .retry_deadline
                    .is_some_and(|deadline| deadline <= now);
            if !closing_retry {
                return Err(ChallengeCoordinatorError::DisputeBondWindow);
            }
        }
        Ok(())
    }

    /// Return a collected filing fee once the signed funding horizon has
    /// closed and no dispute bond ever became durable.
    ///
    /// The original fee and its compensation have distinct semantic keys.
    /// A crash after either rail observation therefore resumes without a
    /// second debit or credit. A still-live filing is left untouched so a
    /// transient bond-rail outage can retry and complete normally.
    fn recover_expired_fee_only_submission(
        &self,
        challenge: &FindingChallenge,
        challenge_envelope_sha256: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        terms: &chio_finding::FindingMarketTerms,
        pool: &chio_finding::FindingPoolBinding,
        now: u64,
    ) -> Result<ExpiredFeeOnlyRecovery, ChallengeCoordinatorError> {
        let Some(recorded) = self
            .challenges
            .get_challenge(&challenge.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
        else {
            return Ok(ExpiredFeeOnlyRecovery::Unchanged);
        };
        let owner_hex = submission.challenger.to_hex();
        if recorded.state != FindingChallengeState::Submitted
            || recorded.challenge_envelope_sha256 != challenge_envelope_sha256
            || recorded.finding_id != challenge.finding_id
            || recorded.listing_id != challenge.listing_id
            || recorded.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission
            || recorded.challenger_hex.as_deref() != Some(owner_hex.as_str())
            || self
                .challenges
                .get_dispute_lock(&challenge.challenge_id)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
                .is_some()
        {
            return Ok(ExpiredFeeOnlyRecovery::Unchanged);
        }
        let filing_deadline = terms
            .issued_at
            .checked_add(terms.filing_window_secs)
            .ok_or(ChallengeCoordinatorError::FilingWindowClosed)?;
        let expired = now > filing_deadline
            || now >= terms.expires_at
            || now >= submission.dispute_lock_ref.expiry;
        if !expired {
            return Ok(ExpiredFeeOnlyRecovery::Unchanged);
        }

        let fee = &submission.dispute_fee_terminal;
        let collected_instruction = FindingRailInstruction {
            idempotency_key: dispute_fee_intent_key(&challenge.challenge_id),
            payer: fee.payer.to_hex(),
            amount_units: fee.amount.units,
            currency: fee.amount.currency.clone(),
            pool_principal_id: fee.beneficiary_pool_principal_id.clone(),
            rail_destination: fee.rail_destination.clone(),
        };
        let collected_digest = canonical_digest_of(&collected_instruction)?;
        let collected = self
            .challenges
            .get_effect_intent(&collected_instruction.idempotency_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let Some(collected) = collected else {
            return Ok(ExpiredFeeOnlyRecovery::Unchanged);
        };
        if collected.kind != FindingEffectIntentKind::Fee
            || collected.liability_key.is_some()
            || collected.settlement_required
            || collected.intent_digest != collected_digest
            || collected.state == FindingEffectIntentState::Quarantined
        {
            return Ok(ExpiredFeeOnlyRecovery::Unchanged);
        }
        if matches!(
            collected.state,
            FindingEffectIntentState::Pending
                | FindingEffectIntentState::Dispatched
                | FindingEffectIntentState::Failed
        ) {
            // The debit may already have reached the rail even though its
            // response did not. Replay the exact durable instruction under
            // its idempotency key before compensating it. This recovery runs
            // before the filing-window check, so expiry cannot strand an
            // uncertain external debit in a nonterminal local state.
            self.charge_dispute_fee(&challenge.challenge_id, submission, now)?;
        }
        let funding_key = derive_dispute_bond_funding_intent_key(
            &challenge.challenge_id,
            &submission.dispute_lock_ref.lock_id,
        );
        let funding = self
            .challenges
            .get_effect_intent(&funding_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        if let Some(intent) = &funding {
            if intent.state == FindingEffectIntentState::Confirmed {
                return Ok(ExpiredFeeOnlyRecovery::FundingConfirmed {
                    received_at: recorded.submitted_at,
                });
            }
            if intent.state == FindingEffectIntentState::Quarantined {
                return Ok(ExpiredFeeOnlyRecovery::Unchanged);
            }
            if matches!(
                intent.state,
                FindingEffectIntentState::Dispatched | FindingEffectIntentState::Failed
            ) {
                let lock = &submission.dispute_lock_ref;
                let input = FindingDisputeLockInput {
                    lock_id: &lock.lock_id,
                    challenge_id: &challenge.challenge_id,
                    owner_hex: &owner_hex,
                    schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
                    amount_units: lock.amount.units,
                    currency: &lock.amount.currency,
                    pool_principal_id: &pool.principal_id,
                    pool_rail_destination: &pool.rail_destination,
                    pool_authority_epoch: pool.authority_epoch,
                    expires_at: lock.expiry,
                    locked_at: recorded.submitted_at,
                };
                let expected_digest = dispute_bond_funding_intent_digest(&input);
                if intent.kind != FindingEffectIntentKind::ChallengeBond
                    || intent.liability_key.is_some()
                    || intent.settlement_required
                    || intent.intent_digest != expected_digest
                {
                    return Ok(ExpiredFeeOnlyRecovery::Unchanged);
                }
                self.challenges
                    .advance_effect_intent(&funding_key, FindingEffectIntentState::Dispatched, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                let instruction = FindingRailInstruction {
                    idempotency_key: funding_key.clone(),
                    payer: owner_hex,
                    amount_units: lock.amount.units,
                    currency: lock.amount.currency.clone(),
                    pool_principal_id: pool.principal_id.clone(),
                    rail_destination: pool.rail_destination.clone(),
                };
                let instruction_digest = canonical_digest_of(&instruction)?;
                match self.rail.dispatch(&instruction) {
                    Ok(observation)
                        if rail_observation_matches(
                            &instruction,
                            &instruction_digest,
                            &observation,
                        ) =>
                    {
                        self.challenges
                            .advance_effect_intent(
                                &funding_key,
                                FindingEffectIntentState::Confirmed,
                                now,
                            )
                            .map_err(|error| {
                                ChallengeCoordinatorError::ChallengeStore(error.to_string())
                            })?;
                        return Ok(ExpiredFeeOnlyRecovery::FundingConfirmed {
                            received_at: recorded.submitted_at,
                        });
                    }
                    Ok(_) => {
                        let _ = self.challenges.advance_effect_intent(
                            &funding_key,
                            FindingEffectIntentState::Failed,
                            now,
                        );
                        return Err(ChallengeCoordinatorError::DisputeBondRail(
                            "rail observation does not reconcile to the dispatched instruction"
                                .to_owned(),
                        ));
                    }
                    Err(reason) => {
                        let _ = self.challenges.advance_effect_intent(
                            &funding_key,
                            FindingEffectIntentState::Failed,
                            now,
                        );
                        return Err(ChallengeCoordinatorError::DisputeBondRail(reason));
                    }
                }
            }
        }

        let (_returned_fee_key, returned_fee_digest) =
            self.return_dispute_fee(&challenge.challenge_id, submission, pool, now)?;
        let lock = &submission.dispute_lock_ref;
        let funding_input = FindingDisputeLockInput {
            lock_id: &lock.lock_id,
            challenge_id: &challenge.challenge_id,
            owner_hex: &owner_hex,
            schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
            amount_units: lock.amount.units,
            currency: &lock.amount.currency,
            pool_principal_id: &pool.principal_id,
            pool_rail_destination: &pool.rail_destination,
            pool_authority_epoch: pool.authority_epoch,
            expires_at: lock.expiry,
            locked_at: recorded.submitted_at,
        };
        let funding_digest = dispute_bond_funding_intent_digest(&funding_input);
        self.challenges
            .close_compensated_unfunded_filing(
                &challenge.challenge_id,
                &collected_digest,
                &returned_fee_digest,
                &lock.lock_id,
                &funding_digest,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(ExpiredFeeOnlyRecovery::Compensated)
    }

    /// Recover the venue receipt time only when this exact challenge and
    /// this exact admission-pinned bond already reached confirmed funding.
    /// This lets a crash after the debit reconstruct and return an expired
    /// lock without treating a fresh backdated filing as timely.
    fn confirmed_funded_submission_received_at(
        &self,
        challenge: &FindingChallenge,
        challenge_envelope_sha256: &str,
        submission: &chio_finding::FindingBuyerSubmission,
        pool: &chio_finding::FindingPoolBinding,
    ) -> Result<Option<u64>, ChallengeCoordinatorError> {
        let Some(recorded) = self
            .challenges
            .get_challenge(&challenge.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
        else {
            return Ok(None);
        };
        let owner_hex = submission.challenger.to_hex();
        if recorded.challenge_envelope_sha256 != challenge_envelope_sha256
            || recorded.finding_id != challenge.finding_id
            || recorded.listing_id != challenge.listing_id
            || recorded.authorization_branch != FindingChallengeAuthorizationBranch::BuyerSubmission
            || recorded.challenger_hex.as_deref() != Some(owner_hex.as_str())
        {
            return Ok(None);
        }
        let lock = &submission.dispute_lock_ref;
        let input = FindingDisputeLockInput {
            lock_id: &lock.lock_id,
            challenge_id: &challenge.challenge_id,
            owner_hex: &owner_hex,
            schedule_envelope_sha256: &lock.fee_schedule_envelope_sha256,
            amount_units: lock.amount.units,
            currency: &lock.amount.currency,
            pool_principal_id: &pool.principal_id,
            pool_rail_destination: &pool.rail_destination,
            pool_authority_epoch: pool.authority_epoch,
            expires_at: lock.expiry,
            locked_at: recorded.submitted_at,
        };
        let key = derive_dispute_bond_funding_intent_key(&challenge.challenge_id, &lock.lock_id);
        let confirmed = self
            .challenges
            .get_effect_intent(&key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .is_some_and(|intent| {
                intent.kind == FindingEffectIntentKind::ChallengeBond
                    && intent.liability_key.is_none()
                    && !intent.settlement_required
                    && intent.intent_digest == dispute_bond_funding_intent_digest(&input)
                    && intent.state == FindingEffectIntentState::Confirmed
            });
        Ok(confirmed.then_some(recorded.submitted_at))
    }
}
