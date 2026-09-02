// Role, terms, fee-schedule, and governance pin requirements.

impl FindingChallengeCoordinator {
    /// Require the fee and bond a buyer submission carries to be the ones
    /// the admitted market terms pinned and the signed fee schedule
    /// priced.
    ///
    /// The two shipped fee event kinds are hard-pinned to the audit pool
    /// so a seller cannot redirect participation fees. The dispute fee is
    /// the third charge path and is pinned just as hard, in the other
    /// direction: it reaches the challenge-administration pool or it does
    /// not settle.
    ///
    /// The amounts are then held to the schedule the filing itself names.
    /// A submission that binds a schedule digest but is never checked
    /// against the schedule behind it prices its own filing, which leaves
    /// the stake a frivolous challenge risks entirely to the challenger.
    fn require_dispute_terms(
        &self,
        submission: &chio_finding::FindingBuyerSubmission,
        admission: &SignedFindingAdmission,
        pool: &chio_finding::FindingPoolBinding,
        received_at: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let fee = &submission.dispute_fee_terminal;
        if fee.beneficiary_pool_principal_id != pool.principal_id
            || fee.rail_destination != pool.rail_destination
            || fee.amount.currency != pool.currency
        {
            return Err(ChallengeCoordinatorError::DisputeFeePool);
        }
        if fee.payer != submission.challenger {
            return Err(ChallengeCoordinatorError::DisputeFeePayer);
        }
        let lock = &submission.dispute_lock_ref;
        if lock.expiry <= received_at {
            return Err(ChallengeCoordinatorError::DisputeBondWindow);
        }
        if lock.amount.currency != pool.currency {
            return Err(ChallengeCoordinatorError::DisputeBondCurrency);
        }
        // The fee and the bond are two halves of one filing and one
        // schedule prices both. A submission naming two would take its fee
        // from the cheaper and its stake from the smaller.
        if fee.fee_schedule_envelope_sha256 != lock.fee_schedule_envelope_sha256 {
            return Err(ChallengeCoordinatorError::DisputeTerms(
                "fee_schedule_envelope_sha256",
            ));
        }
        let terms = self
            .resolve_fee_schedule(admission, &fee.fee_schedule_envelope_sha256)?
            .body;
        // A schedule that has not been issued yet, or that has expired,
        // prices nothing: the window a filing is admitted in is the window
        // its own schedule is live in.
        if received_at < terms.issued_at
            || terms.expires_at.is_some_and(|expiry| received_at >= expiry)
        {
            return Err(ChallengeCoordinatorError::DisputeTerms("filing window"));
        }
        if fee.amount.units != terms.dispute_fee.units
            || fee.amount.currency != terms.dispute_fee.currency
        {
            return Err(ChallengeCoordinatorError::DisputeTerms("dispute fee"));
        }
        // The dispute-class requirement is unique in a schedule its own
        // validator accepted, and it fixes the stake exactly: a smaller
        // bond underprices a frivolous filing, and a larger one would let
        // a forfeiture take more than any signed schedule authorizes.
        let requirement = terms
            .bond_requirements
            .iter()
            .find(|requirement| requirement.bond_class == OpenMarketBondClass::Dispute)
            .ok_or(ChallengeCoordinatorError::DisputeTerms(
                "dispute bond requirement",
            ))?;
        if lock.amount.units != requirement.required_amount.units
            || lock.amount.currency != requirement.required_amount.currency
        {
            return Err(ChallengeCoordinatorError::DisputeTerms("dispute bond"));
        }
        Ok(())
    }

    /// Require the evaluator key to be live at the instant it would sign.
    fn require_live_evaluator_key(
        &self,
        request: &ChallengeEvaluationRequest<'_>,
    ) -> Result<(), ChallengeCoordinatorError> {
        let pin = &self.evaluator_pin;
        if request.evaluator_key_epoch != pin.key_epoch {
            return Err(ChallengeCoordinatorError::EvaluatorKeyEpoch);
        }
        if !pin.covers(request.now) {
            return Err(ChallengeCoordinatorError::EvaluatorKeyWindow);
        }
        self.require_live_role(pin, request.now, request.now, "evaluator")
            .map_err(|error| match error {
                ChallengeCoordinatorError::AuthorityLifecycle { reason, .. } => {
                    ChallengeCoordinatorError::EvaluatorRevocation(reason)
                }
                other => other,
            })?;
        Ok(())
    }

    fn require_live_settlement_observer(
        &self,
        snapshot: &SignedFindingFinalizedBondSnapshot,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let pin = &self.pins.settlement_observer;
        self.require_current_role(pin, snapshot.body.observed_at, now, "settlement observer")
            .map_err(|error| match error {
                ChallengeCoordinatorError::AuthorityLifecycle { reason, .. } => {
                    ChallengeCoordinatorError::SettlementObserverLifecycle(reason)
                }
                other => other,
            })?;
        // `operator_key_epoch` belongs to the independently re-read on-chain
        // vault operator. The envelope signer is authenticated by `pin`; the
        // chain observation validates its own operator identity and epoch.
        Ok(())
    }

    /// Authenticate a newly consumed live input or newly signed output at
    /// both its declared action time and the current venue clock. Historical
    /// artifacts continue to use `require_live_role`; this stronger boundary
    /// prevents a retired key from backdating new unanchored evidence or
    /// signing a new artifact under its former lifecycle.
    fn require_current_role(
        &self,
        pin: &FindingAuthorityPin,
        acted_at: u64,
        now: u64,
        role: &'static str,
    ) -> Result<PublicKey, ChallengeCoordinatorError> {
        let (key, status) = self.resolve_live_role(pin, acted_at, now, role)?;
        let reject = |reason| ChallengeCoordinatorError::AuthorityLifecycle { role, reason };
        if !pin.covers(now) {
            return Err(reject("authority pin is not live at the venue clock"));
        }
        if status
            .body
            .revoked_from
            .is_some_and(|revoked_from| revoked_from <= now)
        {
            return Err(reject("key is revoked at the venue clock"));
        }
        Ok(key)
    }

    /// Authenticate one role's exact lifecycle policy against the
    /// governance-signed reading returned by the deployment resolver.
    fn require_live_role(
        &self,
        pin: &FindingAuthorityPin,
        acted_at: u64,
        now: u64,
        role: &'static str,
    ) -> Result<PublicKey, ChallengeCoordinatorError> {
        self.resolve_live_role(pin, acted_at, now, role)
            .map(|(key, _)| key)
    }

    fn resolve_live_role(
        &self,
        pin: &FindingAuthorityPin,
        acted_at: u64,
        now: u64,
        role: &'static str,
    ) -> Result<(PublicKey, SignedFindingAuthorityStatus), ChallengeCoordinatorError> {
        let reject = |reason| ChallengeCoordinatorError::AuthorityLifecycle { role, reason };
        if acted_at > now {
            return Err(reject("role action is ahead of the venue clock"));
        }
        if !pin.covers(acted_at) {
            return Err(reject(
                "role action is outside the configured validity window",
            ));
        }
        let signed = self
            .authority_status
            .resolve(pin, now)
            .map_err(|_| reject("revocation source could not be resolved"))?;
        let status_key = self
            .pins
            .authority_status
            .key()
            .map_err(|_| reject("status authority pin is invalid"))?;
        verify_pinned_envelope(&signed, &status_key, "authority status")
            .map_err(|_| reject("revocation status signature is invalid"))?;
        let body = &signed.body;
        if !self.pins.authority_status.covers(body.observed_at)
            || !self.pins.authority_status.covers(now)
        {
            return Err(reject(
                "status authority is outside its configured validity window",
            ));
        }
        let key = pin.key().map_err(|_| reject("authority pin is invalid"))?;
        if body.schema != FINDING_AUTHORITY_STATUS_SCHEMA_V1
            || body.status_ref != pin.revocation_status_ref
            || body.authority_id != pin.authority_id
            || body.key != key
            || body.key_epoch != pin.key_epoch
        {
            return Err(reject("revocation status does not bind the configured pin"));
        }
        if body.observed_at < acted_at
            || body.observed_at > now
            || now.saturating_sub(body.observed_at) > MAX_REVOCATION_STATUS_AGE_SECS
        {
            return Err(reject(
                "revocation status is not a fresh post-action reading",
            ));
        }
        if body
            .revoked_from
            .is_some_and(|revoked_from| revoked_from > body.observed_at)
        {
            return Err(reject(
                "revocation status declares an unobserved future event",
            ));
        }
        if body
            .revoked_from
            .is_some_and(|revoked_from| revoked_from <= acted_at)
        {
            return Err(reject("key was revoked when the role acted"));
        }
        Ok((key, signed))
    }

    /// Require a bondless venue audit to be one the published round drew.
    ///
    /// The audit branch is the only filing that stakes nothing, so the
    /// round is the whole of what stands between it and an unbounded free
    /// challenge. Verifying that the pinned audit authority signed the
    /// envelope proves who filed, never what was drawn: the three digests
    /// the branch carries have to resolve to a published round and to the
    /// draw that round deterministically produces for this exact listing.
    fn require_audit_selection(
        &self,
        audit: &chio_finding::FindingVenueAuditAuthorization,
        challenge: &FindingChallenge,
        admission: &SignedFindingAdmission,
        now: u64,
    ) -> Result<ResolvedFindingAuditSelection, ChallengeCoordinatorError> {
        let round = self
            .filings
            .audit_round(&audit.audit_epoch_envelope_sha256)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownAuditRound)?;
        // Re-derived from the resolved envelope, so a resolver answering
        // with any other round is caught here rather than authorizing a
        // filing against a round the audit never named.
        if self.envelope_digest(&round.epoch)? != audit.audit_epoch_envelope_sha256 {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "audit_epoch_envelope_sha256",
            ));
        }
        let historical_policy = self
            .filings
            .audit_policy_for_epoch(&audit.audit_epoch_envelope_sha256)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownAuditAuthorityPolicy)?;
        let audit_authority = self.require_live_role(
            &historical_policy,
            round.epoch.body.committed_at,
            now,
            "historical audit",
        )?;
        let witness_policy = self
            .filings
            .randomness_witness_policy_for_epoch(&audit.audit_epoch_envelope_sha256)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownAuditRandomnessWitnessPolicy)?;
        let randomness_witness = self.require_live_role(
            &witness_policy,
            round.epoch.body.seed_witnessed_at,
            now,
            "historical audit randomness witness",
        )?;
        verify_signed_audit_epoch(&round.epoch, &audit_authority, &randomness_witness)
            .map_err(|error| ChallengeCoordinatorError::AuditEpoch(error.to_string()))?;
        let authorization_digest = self.envelope_digest(&round.authorization)?;
        if round.epoch.body.authorization_digest != authorization_digest
            || audit.authorization_digest != authorization_digest
        {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "authorization_digest",
            ));
        }
        round
            .authorization
            .body
            .validate()
            .map_err(|_| ChallengeCoordinatorError::AuditRoundBinding("authorization_body"))?;
        let governance_policy = self
            .filings
            .governance_policy_for_audit_authorization(&authorization_digest)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownAuditGovernancePolicy)?;
        let governance_authority = self.require_live_role(
            &governance_policy,
            round.authorization.body.authorized_at,
            now,
            "historical audit governance",
        )?;
        verify_signed_audit_round_authorization(&round.authorization, &governance_authority)
            .map_err(|_| ChallengeCoordinatorError::AuditRoundBinding("authorization_signature"))?;
        if round.authorization.body.authorized_at > round.epoch.body.committed_at
            || round.authorization.body.expires_at <= round.epoch.body.committed_at
            || round.authorization.body.epoch_precommitment_sha256
                != audit_epoch_precommitment_sha256(&round.epoch.body)
                    .map_err(|_| ChallengeCoordinatorError::Canonical)?
        {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "authorization_epoch",
            ));
        }
        if challenge.filed_at <= round.epoch.body.committed_at {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "filing_after_epoch",
            ));
        }
        if round.epoch.body.fee_schedule_envelope_sha256
            != admission.body.fee_schedule_envelope_sha256
        {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "fee_schedule_envelope_sha256",
            ));
        }
        // The selection is a pure function of inputs the epoch committed
        // to before the seed was revealed, so it is recomputed here rather
        // than read from anything the filing carries. A listing the round
        // never drew has no entry to find.
        let selection = select_audit_targets(
            &round.epoch.body,
            &randomness_witness,
            &round.revealed_seed,
            &round.eligible,
        )
        .map_err(|error| ChallengeCoordinatorError::AuditSelection(error.to_string()))?;
        let drawn = selection
            .iter()
            .find(|target| {
                target.finding_id == challenge.finding_id
                    && target.listing_id == challenge.listing_id
            })
            .ok_or(ChallengeCoordinatorError::AuditRoundBinding("selection"))?;
        if drawn.draw != audit.selection_digest {
            return Err(ChallengeCoordinatorError::AuditRoundBinding(
                "selection_digest",
            ));
        }
        Ok(ResolvedFindingAuditSelection {
            round,
            audit_authority,
            randomness_witness,
            governance_authority,
        })
    }

    /// Resolve the signed fee schedule one filing bound by digest, and
    /// prove it is the exact schedule the retained venue admission
    /// authorized.
    ///
    /// The digest is re-derived from the resolved envelope, so a resolver
    /// answering with any other artifact is caught here rather than
    /// pricing the filing. The admission was authenticated under the venue
    /// policy that covered its issue time, so later fee-operator rotation
    /// cannot strand a historical filing. The schedule still verifies
    /// strictly under the signer whose exact envelope the admission bound.
    fn resolve_fee_schedule(
        &self,
        admission: &SignedFindingAdmission,
        envelope_sha256: &str,
    ) -> Result<SignedOpenMarketFeeSchedule, ChallengeCoordinatorError> {
        if admission.body.fee_schedule_envelope_sha256 != envelope_sha256 {
            return Err(ChallengeCoordinatorError::DisputeTerms(
                "fee_schedule_envelope_sha256",
            ));
        }
        let schedule = self
            .filings
            .fee_schedule(envelope_sha256)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownFeeSchedule)?;
        if self.envelope_digest(&schedule)? != envelope_sha256 {
            return Err(ChallengeCoordinatorError::DisputeTerms(
                "resolved fee schedule digest",
            ));
        }
        verify_pinned_envelope(&schedule, &schedule.signer_key, "fee schedule")
            .map_err(|error| ChallengeCoordinatorError::FeeScheduleArtifact(error.to_string()))?;
        schedule
            .body
            .validate()
            .map_err(ChallengeCoordinatorError::FeeScheduleArtifact)?;
        Ok(schedule)
    }

    /// The listing-class requirement is unique in a validated schedule and
    /// is the only ceiling the penalty calculation may use.
    fn listing_bond_requirement(
        schedule: &SignedOpenMarketFeeSchedule,
    ) -> Result<&MonetaryAmount, ChallengeCoordinatorError> {
        schedule
            .body
            .bond_requirements
            .iter()
            .find(|requirement| requirement.bond_class == OpenMarketBondClass::Listing)
            .map(|requirement| &requirement.required_amount)
            .ok_or(ChallengeCoordinatorError::DisputeTerms(
                "listing bond requirement",
            ))
    }

    /// Resolve the seller-signed market terms one filing binds by digest,
    /// and prove they are the terms this venue admitted for the exact
    /// finding artifact and listing being challenged.
    ///
    /// The digest is re-derived from the resolved envelope, so a resolver
    /// answering with any other artifact is caught here. The envelope must
    /// verify under its embedded seller, and it must name the challenged
    /// finding bytes and listing: terms for another artifact or listing
    /// would lend this filing a window, an audit toggle, and bond limits
    /// their seller never signed for it.
    fn resolve_market_terms(
        &self,
        challenge: &FindingChallenge,
    ) -> Result<SignedFindingMarketTerms, ChallengeCoordinatorError> {
        let terms = self
            .filings
            .market_terms(&challenge.terms_envelope_sha256)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownMarketTerms)?;
        if self.envelope_digest(&terms)? != challenge.terms_envelope_sha256 {
            return Err(ChallengeCoordinatorError::FilingTermsBinding(
                "envelope digest",
            ));
        }
        verify_signed_market_terms(&terms)
            .map_err(|error| ChallengeCoordinatorError::TermsEnvelope(error.to_string()))?;
        if terms.body.finding_id != challenge.finding_id {
            return Err(ChallengeCoordinatorError::FilingTermsBinding("finding_id"));
        }
        if terms.body.finding_artifact_sha256 != challenge.finding_artifact_sha256 {
            return Err(ChallengeCoordinatorError::FilingTermsBinding(
                "finding_artifact_sha256",
            ));
        }
        if terms.body.verifier_profile_envelope_sha256 != challenge.profile_envelope_sha256 {
            return Err(ChallengeCoordinatorError::FilingTermsBinding(
                "verifier_profile_envelope_sha256",
            ));
        }
        if terms.body.listing_id != challenge.listing_id {
            return Err(ChallengeCoordinatorError::FilingTermsBinding("listing_id"));
        }
        if terms.body.appeal_window_secs < MIN_APPEAL_WINDOW_SECS {
            return Err(ChallengeCoordinatorError::DisputeTerms("appeal window"));
        }
        Ok(terms)
    }

    /// Require both the signed filing instant and the venue's receipt
    /// instant to sit inside the seller-signed filing window.
    ///
    /// The window is the exposure horizon the seller committed to when
    /// the terms were issued: `filing_window_secs` from their issuance is
    /// how long a challenge may still be filed against the listing. A
    /// self-signed `filed_at` alone is not an authoritative receipt
    /// clock: a caller could backdate a freshly signed filing after the
    /// deadline. The signed instant still has to follow terms issuance,
    /// and the venue clock must not have crossed the same deadline. A
    /// window end that is not representable admits nothing.
    fn require_filing_window(
        &self,
        terms: &chio_finding::FindingMarketTerms,
        filed_at: u64,
        received_at: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let deadline = terms
            .issued_at
            .checked_add(terms.filing_window_secs)
            .ok_or(ChallengeCoordinatorError::FilingWindowClosed)?;
        if filed_at < terms.issued_at
            || filed_at > deadline
            || received_at > deadline
            || filed_at >= terms.expires_at
            || received_at >= terms.expires_at
        {
            return Err(ChallengeCoordinatorError::FilingWindowClosed);
        }
        Ok(())
    }

    /// Require a buyer's dispute bond to sit inside the seller-signed
    /// bond limits for the challenged finding's guarantee class.
    ///
    /// The signed fee schedule fixes the bond exactly; these limits are
    /// the seller's own anti-griefing floor and ceiling, signed into the
    /// terms per guarantee class. Both artifacts must agree: a schedule
    /// pricing the bond outside the seller's signed band, or a class the
    /// terms never priced, refuses the filing.
    fn require_bond_within_terms_limits(
        &self,
        terms: &chio_finding::FindingMarketTerms,
        submission: &chio_finding::FindingBuyerSubmission,
        guarantee_class: chio_finding::FindingGuaranteeClass,
    ) -> Result<(), ChallengeCoordinatorError> {
        let limit = terms
            .challenge_bond_limits
            .iter()
            .find(|limit| limit.guarantee_class == guarantee_class)
            .ok_or(ChallengeCoordinatorError::DisputeBondOutsideTermsLimits)?;
        let bond = &submission.dispute_lock_ref.amount;
        if bond.currency != limit.min_bond.currency
            || bond.units < limit.min_bond.units
            || bond.units > limit.max_bond.units
        {
            return Err(ChallengeCoordinatorError::DisputeBondOutsideTermsLimits);
        }
        Ok(())
    }

    /// Require every governance artifact behind a penalty to carry a
    /// pinned signature.
    ///
    /// The charter, the case, and the activation are governance-root
    /// artifacts; the fee schedule verifies against its own operator
    /// roster; a superseded penalty can only be one this lane signed. The
    /// listing is left to the namespace-owner rule the penalty surface
    /// applies, and is bound to the case, which is pinned here.
    fn require_pinned_governance(
        &self,
        governance: &FindingPenaltyGovernance<'_>,
        case: &SignedGenericGovernanceCase,
        prior_penalty: Option<&SignedOpenMarketPenalty>,
        now: u64,
    ) -> Result<Vec<PublicKey>, ChallengeCoordinatorError> {
        let case_envelope_sha256 = self.envelope_digest(case)?;
        let governance_policy = self
            .filings
            .governance_policy_for_case(&case_envelope_sha256)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownGovernanceCasePolicy)?;
        let governance_key = self.require_live_role(
            &governance_policy,
            case.body.updated_at,
            now,
            "historical governance case",
        )?;
        let charter_envelope_sha256 = self.envelope_digest(governance.charter)?;
        let charter_policy = self
            .filings
            .governance_policy_for_case(&charter_envelope_sha256)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .unwrap_or_else(|| governance_policy.clone());
        let charter_governance_key = self.require_live_role(
            &charter_policy,
            governance.charter.body.issued_at,
            now,
            "historical governance charter",
        )?;
        // The listing authenticates against its own namespace owner rather
        // than a pinned key, so the case is what anchors it: a listing the
        // pinned case does not name cannot be the one being sanctioned.
        if governance.listing.body.listing_id != case.body.listing_id {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "penalty listing",
            ));
        }
        let schedule_digest = self.envelope_digest(governance.fee_schedule)?;
        if governance.admission.body.listing_id != case.body.listing_id
            || governance.admission.body.fee_schedule_envelope_sha256 != schedule_digest
        {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "admitted fee schedule",
            ));
        }
        let admission_digest = self.envelope_digest(governance.admission)?;
        let venue_policy = self
            .filings
            .venue_policy_for_admission(&admission_digest)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownAdmission)?;
        let historical_venue = self.require_live_role(
            &venue_policy,
            governance.admission.body.issued_at,
            now,
            "historical venue",
        )?;
        verify_signed_admission(governance.admission, &historical_venue, &self.venue_id)
            .map_err(|error| ChallengeCoordinatorError::AdmissionEnvelope(error.to_string()))?;
        if governance.charter.signer_key != charter_governance_key {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "governance charter",
            ));
        }
        if case.signer_key != governance_key {
            return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                "governance case",
            ));
        }
        let mut trusted = vec![governance_key, charter_governance_key];
        if let Some(activation) = governance.activation {
            let activation_digest = self.envelope_digest(activation)?;
            let activation_policy = self
                .filings
                .governance_policy_for_activation(&activation_digest)
                .map_err(ChallengeCoordinatorError::FilingResolver)?
                .ok_or(ChallengeCoordinatorError::UnknownGovernanceActivationPolicy)?;
            let activation_at = activation
                .body
                .reviewed_at
                .unwrap_or(activation.body.requested_at);
            let activation_key = self.require_live_role(
                &activation_policy,
                activation_at,
                now,
                "historical trust activation",
            )?;
            if activation.signer_key != activation_key {
                return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                    "trust activation",
                ));
            }
            if !trusted.contains(&activation_key) {
                trusted.push(activation_key);
            }
        }
        if let Some(prior) = prior_penalty {
            let prior_digest = self.envelope_digest(prior)?;
            let prior_policy = self
                .filings
                .penalty_policy_for_penalty(&prior_digest)
                .map_err(ChallengeCoordinatorError::FilingResolver)?
                .ok_or(ChallengeCoordinatorError::UnknownPenaltyAuthorityPolicy)?;
            let prior_key = self.require_live_role(
                &prior_policy,
                prior.body.updated_at,
                now,
                "historical prior penalty",
            )?;
            if prior.signer_key != prior_key {
                return Err(ChallengeCoordinatorError::AuthorityPinMismatch(
                    "prior penalty",
                ));
            }
            if !trusted.contains(&prior_key) {
                trusted.push(prior_key);
            }
        }
        ensure_generic_listing_signed_by_namespace_owner(governance.listing, "penalty listing")
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        governance
            .fee_schedule
            .body
            .validate()
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        if !governance
            .fee_schedule
            .verify_signature()
            .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
        {
            return Err(ChallengeCoordinatorError::PenaltyMint(
                "fee schedule signature is invalid".to_owned(),
            ));
        }
        governance
            .charter
            .body
            .validate()
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        if !governance
            .charter
            .verify_signature()
            .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
        {
            return Err(ChallengeCoordinatorError::PenaltyMint(
                "governance charter signature is invalid".to_owned(),
            ));
        }
        case.body
            .validate()
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        if !case
            .verify_signature()
            .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
        {
            return Err(ChallengeCoordinatorError::PenaltyMint(
                "governance case signature is invalid".to_owned(),
            ));
        }
        if let Some(activation) = governance.activation {
            activation
                .body
                .validate()
                .map_err(ChallengeCoordinatorError::PenaltyMint)?;
            if !activation
                .verify_signature()
                .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
            {
                return Err(ChallengeCoordinatorError::PenaltyMint(
                    "trust activation signature is invalid".to_owned(),
                ));
            }
        }
        if let Some(prior) = prior_penalty {
            prior
                .body
                .validate()
                .map_err(ChallengeCoordinatorError::PenaltyMint)?;
            if !prior
                .verify_signature()
                .map_err(|error| ChallengeCoordinatorError::PenaltyMint(error.to_string()))?
            {
                return Err(ChallengeCoordinatorError::PenaltyMint(
                    "prior penalty signature is invalid".to_owned(),
                ));
            }
        }
        governance
            .current_publisher
            .validate()
            .map_err(ChallengeCoordinatorError::PenaltyMint)?;
        Ok(trusted)
    }
}
