// Challenge evaluation, terminal recovery, and dispute-bond disposal.

impl FindingChallengeCoordinator {
    /// Adjudicate one challenge: admit the attempt, delegate the decision
    /// to the pure evaluator, sign the outcome under the evaluator role,
    /// record the verdict, and dispose the bond the verdict calls for.
    ///
    /// An inadmissible submission produces no verdict and no signed
    /// outcome. Its durable state remains submitted, so a funded filing
    /// can still reach its ordinary expiry and bond-return path rather than
    /// becoming stranded in evaluation.
    ///
    /// The evaluator key's own lifecycle is proved before the attempt is
    /// admitted, so a key that has expired, that is revoked, or that is
    /// not in the epoch the caller declares leaves the challenge exactly
    /// where it was rather than consuming an attempt against it.
    pub fn evaluate(
        &self,
        request: &ChallengeEvaluationRequest<'_>,
    ) -> Result<Option<ChallengeEvaluationOutcome>, ChallengeCoordinatorError> {
        if let Some(recovered) = self.recover_terminal_evaluation(request)? {
            return Ok(Some(recovered));
        }
        self.require_live_evaluator_key(request)?;
        let body = &request.challenge.body;
        let admission = self.resolve_admission(body, request.now)?;
        let purchase_authority_status = self.require_authoritative_purchase_standing(
            &admission,
            request.evidence,
            request.now,
        )?;
        self.require_failed_delivery_reservation_binding(body, request.evidence, &admission)?;
        if request.collateral.bond_snapshot.body.allocation_id
            != admission.body.backing_allocation_id
        {
            return Err(ChallengeCoordinatorError::CollateralAllocation);
        }
        let schedule =
            self.resolve_fee_schedule(&admission, &admission.body.fee_schedule_envelope_sha256)?;
        let listing_requirement = Self::listing_bond_requirement(&schedule)?;
        let terms = self.resolve_market_terms(body)?;
        Self::require_signed_base_stake(&terms, request.collateral)?;
        require_admitted_replay_decision_rule(&terms, &body.evidence)?;
        // Funding admits evaluator work, but the lifecycle transition waits
        // for adjudication so an immutable refusal cannot strand the funded
        // filing in `evaluating`.
        self.require_funded_filing(&body.challenge_id, request.now)?;
        let resolved_audit_selection = match &body.authorization {
            FindingChallengeAuthorization::VenueAudit(audit) => {
                Some(self.require_audit_selection(audit, body, &admission, request.now)?)
            }
            FindingChallengeAuthorization::BuyerSubmission(_) => None,
        };
        let audit_authority = match &resolved_audit_selection {
            Some(selection) => selection.audit_authority.clone(),
            None => self
                .pins
                .audit_authority
                .key()
                .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("audit"))?,
        };
        let audit_randomness_witness = match &resolved_audit_selection {
            Some(selection) => selection.randomness_witness.clone(),
            None => self.pins.audit_randomness_witness.key().map_err(|_| {
                ChallengeCoordinatorError::AuthorityPinMismatch("audit randomness witness")
            })?,
        };
        let profile_envelope_sha256 = self.envelope_digest(request.profile)?;
        if profile_envelope_sha256 != admission.body.profile_envelope_sha256 {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "profile_envelope_sha256",
            ));
        }
        let profile_governance_policy = self
            .filings
            .governance_policy_for_profile(&profile_envelope_sha256)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownProfileGovernancePolicy)?;
        let (governance_authority, governance_authority_status) = self.resolve_live_role(
            &profile_governance_policy,
            request.profile.body.issued_at,
            request.now,
            "historical profile governance",
        )?;
        let pinned_governance_policy = FindingRetainedAuthorityPolicy {
            authority_id: &profile_governance_policy.authority_id,
            key: &governance_authority,
            key_epoch: profile_governance_policy.key_epoch,
            valid_from: profile_governance_policy.valid_from,
            valid_until: profile_governance_policy.valid_until,
            revocation_status_ref: &profile_governance_policy.revocation_status_ref,
        };
        let authority_status_key = self
            .pins
            .authority_status
            .key()
            .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("authority status"))?;
        let venue_audit_selection =
            resolved_audit_selection
                .as_ref()
                .map(|selection| FindingVenueAuditSelectionEvidence {
                    epoch: &selection.round.epoch,
                    authorization: &selection.round.authorization,
                    revealed_seed: &selection.round.revealed_seed,
                    eligible: &selection.round.eligible,
                    pinned_randomness_witness: &selection.randomness_witness,
                    pinned_governance_authority: &selection.governance_authority,
                });
        let input = FindingChallengeEvaluationInput {
            challenge: request.challenge,
            pinned_audit_authority: &audit_authority,
            pinned_audit_randomness_witness: &audit_randomness_witness,
            pinned_admission_fee_schedule_envelope_sha256: &admission
                .body
                .fee_schedule_envelope_sha256,
            raw_finding: request.raw_finding,
            profile: request.profile,
            governance_authority: &governance_authority,
            pinned_governance_policy,
            governance_authority_status: &governance_authority_status,
            pinned_admission_profile_envelope_sha256: &admission.body.profile_envelope_sha256,
            pinned_purchase_authority: &admission.body.purchase_authority,
            pinned_failed_delivery_authority: &admission.body.failed_delivery_authority,
            purchase_authority_status: purchase_authority_status.as_ref(),
            pinned_authority_status_key: &authority_status_key,
            evaluated_at: request.now,
            venue_audit_selection,
            evidence: request.evidence,
        };
        let FindingChallengeEvaluation::Adjudicated(adjudication) =
            evaluate_finding_challenge(&input)
        else {
            return Ok(None);
        };
        let (verdict, facet, reason) = adjudication.into_parts();
        if verdict == chio_finding::FindingChallengeVerdict::Upheld {
            self.require_impairable_collateral(request.collateral, request.now)?;
        }
        if self.admit_evaluation(&body.challenge_id, request.now)? != EvaluationAdmission::Admitted
        {
            return Ok(None);
        }
        let challenge_envelope_sha256 = self.envelope_digest(request.challenge)?;
        let evidence_bundle_digest = self.evidence_bundle_digest(
            body,
            request.evidence,
            purchase_authority_status.as_ref(),
            &governance_authority_status,
            resolved_audit_selection.as_ref(),
        )?;
        let attempt = self
            .challenges
            .get_challenge(&body.challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .map_or(0, |record| record.retry_count);
        let penalty_calculation = match verdict {
            chio_finding::FindingChallengeVerdict::Upheld => {
                Some(self.checked_penalty_calculation(
                    request.collateral,
                    listing_requirement,
                    request.now,
                )?)
            }
            _ => None,
        };
        let retry_deadline = match verdict {
            chio_finding::FindingChallengeVerdict::Indeterminate if attempt == 0 => {
                self.derive_retry_deadline(body, &terms, request.now)?
            }
            _ => None,
        };
        let mut outcome = FindingChallengeOutcome {
            schema: FINDING_CHALLENGE_OUTCOME_SCHEMA_V1.to_owned(),
            outcome_id: String::new(),
            challenge_envelope_sha256: challenge_envelope_sha256.clone(),
            finding_id: body.finding_id.clone(),
            listing_id: body.listing_id.clone(),
            backing_allocation_id: admission.body.backing_allocation_id.clone(),
            authorization: body.authorization.kind(),
            audit_epoch_envelope_sha256: match &body.authorization {
                chio_finding::FindingChallengeAuthorization::BuyerSubmission(_) => None,
                chio_finding::FindingChallengeAuthorization::VenueAudit(audit) => {
                    Some(audit.audit_epoch_envelope_sha256.clone())
                }
            },
            evidence_kind: body.evidence.kind(),
            verifier_profile_envelope_sha256: profile_envelope_sha256.clone(),
            evidence_bundle_digest: evidence_bundle_digest.clone(),
            verdict,
            facet,
            reason: reason.code().to_owned(),
            trigger_digest: sha256_hex(
                format!(
                    "{TRIGGER_DOMAIN}\0{challenge_envelope_sha256}\0{profile_envelope_sha256}\0{artifact}\0{evidence_bundle_digest}\0{attempt}\0{retry}",
                    artifact = body.finding_artifact_sha256,
                    retry = retry_deadline.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                )
                .as_bytes(),
            ),
            penalty_calculation,
            retry_deadline,
            evaluator_authority_id: self.evaluator_pin.authority_id.clone(),
            evaluator_key: self.evaluator_authority.public_key(),
            // The epoch the outcome carries is the pinned one, which the
            // request has just been held to, so the signed artifact states
            // the deployment's epoch rather than the caller's claim.
            evaluator_key_epoch: self.evaluator_pin.key_epoch,
            evaluator_valid_from: self.evaluator_pin.valid_from,
            evaluator_valid_until: self.evaluator_pin.valid_until,
            evaluator_revocation_status_ref: self
                .evaluator_pin
                .revocation_status_ref
                .clone(),
            evaluated_at: request.now,
        };
        outcome.outcome_id =
            derive_outcome_id(&outcome).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        // The store keeps this envelope forever and the penalty lane binds
        // its digest, so a body its own validator rejects must never be
        // signed.
        outcome
            .validate()
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        let signed = SignedFindingChallengeOutcome::sign_with_backend(
            outcome,
            self.evaluator_authority.as_ref(),
        )
        .map_err(|_| ChallengeCoordinatorError::Signing)?;
        let outcome_envelope_json =
            canonical_json_bytes(&signed).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        let outcome_envelope_sha256 = sha256_hex(&outcome_envelope_json);
        self.filings
            .retain_evaluator_policy(&outcome_envelope_sha256, &self.evaluator_pin)
            .map_err(ChallengeCoordinatorError::EvaluatorPolicyRetention)?;

        let state = match signed.body.penalty_calculation.as_ref() {
            Some(calculation) => self
                .challenges
                .record_authenticated_upheld_verdict_with_exposure_fence(
                    &body.challenge_id,
                    &signed,
                    &self.evaluator_authority.public_key(),
                    &admission.body.backing_allocation_id,
                    calculation.open_per_sale_encumbrance_units,
                    request.now,
                ),
            None => self.challenges.record_authenticated_verdict(
                &body.challenge_id,
                &signed,
                &self.evaluator_authority.public_key(),
                request.now,
            ),
        }
        .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        let bond_disposition = self.dispose_dispute_bond(&body.challenge_id, request.now)?;
        Ok(Some(ChallengeEvaluationOutcome {
            state,
            outcome: signed,
            outcome_envelope_sha256,
            bond_disposition,
        }))
    }

    /// Recover the exact signed artifact for a terminal verdict whose
    /// response or bond disposition was interrupted after the atomic verdict
    /// commit. No re-evaluation occurs and the historical evaluator policy is
    /// authenticated before the retained bytes are returned.
    fn recover_terminal_evaluation(
        &self,
        request: &ChallengeEvaluationRequest<'_>,
    ) -> Result<Option<ChallengeEvaluationOutcome>, ChallengeCoordinatorError> {
        let challenge_id = &request.challenge.body.challenge_id;
        let Some(challenge) = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
        else {
            return Ok(None);
        };
        if !matches!(
            challenge.state,
            FindingChallengeState::Upheld
                | FindingChallengeState::Rejected
                | FindingChallengeState::IndeterminateClosed
        ) {
            return Ok(None);
        }
        let challenge_envelope_sha256 = self.envelope_digest(request.challenge)?;
        if challenge.challenge_envelope_sha256 != challenge_envelope_sha256 {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let outcome_envelope_sha256 =
            challenge
                .outcome_envelope_sha256
                .as_deref()
                .ok_or_else(|| {
                    ChallengeCoordinatorError::ChallengeStore(
                        "terminal challenge has no outcome digest".to_owned(),
                    )
                })?;
        let retained = self
            .challenges
            .get_outcome_envelope(outcome_envelope_sha256)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore(
                    "terminal challenge has no retained outcome envelope".to_owned(),
                )
            })?;
        if retained.challenge_id != *challenge_id {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let outcome: SignedFindingChallengeOutcome =
            serde_json::from_slice(&retained.outcome_envelope_json)
                .map_err(|error| ChallengeCoordinatorError::OutcomeEnvelope(error.to_string()))?;
        let canonical =
            canonical_json_bytes(&outcome).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        if canonical != retained.outcome_envelope_json
            || outcome.body.challenge_envelope_sha256 != challenge_envelope_sha256
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        self.require_recorded_outcome_signature(challenge_id, &outcome, request.now)?;
        let bond_disposition = self.dispose_dispute_bond(challenge_id, request.now)?;
        Ok(Some(ChallengeEvaluationOutcome {
            state: challenge.state,
            outcome,
            outcome_envelope_sha256: outcome_envelope_sha256.to_owned(),
            bond_disposition,
        }))
    }

    /// Apply the bond rule the challenge's terminal state calls for.
    ///
    /// Upheld returns the lock. Rejected applies the predeclared
    /// failed-challenge rule. Indeterminate never forfeits: while the
    /// challenge is still retryable the same lock is retained, and once
    /// it closes the lock is returned. A bondless venue audit has no
    /// disposition under any verdict. The store additionally refuses a
    /// forfeit against anything but a rejected challenge, so this rule
    /// and that fence agree by construction.
    pub fn dispose_dispute_bond(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<Option<FindingDisputeLockDisposition>, ChallengeCoordinatorError> {
        let Some(lock) = self
            .challenges
            .get_dispute_lock(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
        else {
            return Ok(None);
        };
        let challenge = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        let disposition = match challenge.state {
            FindingChallengeState::Upheld | FindingChallengeState::IndeterminateClosed => {
                FindingDisputeLockDisposition::Returned
            }
            FindingChallengeState::Rejected => self.failed_challenge_disposition,
            FindingChallengeState::Submitted
            | FindingChallengeState::Evaluating
            | FindingChallengeState::IndeterminateRetryable => return Ok(None),
        };
        if disposition == FindingDisputeLockDisposition::Returned {
            self.return_dispute_bond(&lock, now)?;
        }
        self.challenges
            .release_dispute_bond(challenge_id, disposition, now)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(Some(disposition))
    }
}
