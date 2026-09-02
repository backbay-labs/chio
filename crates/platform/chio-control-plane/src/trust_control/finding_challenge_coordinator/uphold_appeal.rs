// Uphold decisions and appeal resolution.

impl FindingChallengeCoordinator {
    /// The critical transaction, and everything that has to follow it
    /// before an appeal window can open.
    ///
    /// The terminal upheld verdict has already fenced its signed exposure
    /// and raised the sales block in one transaction. This step freezes the
    /// purchase cutoff and claim deadline while replaying that same block on
    /// the shared connection, so no slot can open above the cutoff. The
    /// claim snapshot then waits on two
    /// conditions. Every slot at or below the frozen cutoff must have
    /// reached a settled record or a denial, because a slot still in
    /// flight is a buyer who may yet belong in it. And the seller-signed
    /// claim window must have elapsed, because the snapshot is immutable:
    /// sealing it the instant adjudication lands would close the payout
    /// against every harmed buyer and omission proof still inside the
    /// window the seller signed for. Only then is the snapshot sealed, the
    /// sanction recorded, and the pending-appeal hold minted and
    /// evaluated.
    ///
    /// Returns [`ChallengeCoordinatorError::ClaimWindowOpen`] until both
    /// hold. That is a retry, not a failure: the liability stays
    /// upheld-pending-claims with sales already blocked, and a later call
    /// replays the compare-and-set as a no-op and continues. It follows
    /// that no single call can both open the window and seal the payout.
    ///
    /// Two preconditions of the hold are checked before a liability is
    /// opened: the governance artifacts must carry pinned signatures, and
    /// the collateral must still fund the evaluator-signed amount. A
    /// failure opens no liability, while the terminal fraud verdict keeps
    /// the listing's fail-closed sales block in place for reconciliation.
    #[allow(clippy::too_many_arguments)]
    pub fn uphold(
        &self,
        challenge_id: &str,
        signed_challenge: &SignedFindingChallenge,
        outcome: &SignedFindingChallengeOutcome,
        identity: &FindingLiabilityIdentity<'_>,
        terms: &SignedFindingMarketTerms,
        cutoff_slot: u64,
        claim_candidates: &[String],
        collateral: &FindingCollateralFacts<'_>,
        governance: &FindingPenaltyGovernance<'_>,
        sanction_case: &SignedGenericGovernanceCase,
        now: u64,
    ) -> Result<UpheldLiability, ChallengeCoordinatorError> {
        self.require_recorded_outcome_signature(challenge_id, outcome, now)?;
        if outcome.body.verdict != chio_finding::FindingChallengeVerdict::Upheld {
            return Err(ChallengeCoordinatorError::VerdictNotUpheld);
        }
        if outcome.body.finding_id != identity.finding_id
            || outcome.body.listing_id != identity.listing_id
            || outcome.body.backing_allocation_id != identity.allocation_id
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        if signed_challenge.body.challenge_id != challenge_id {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let challenge_envelope_sha256 = self.envelope_digest(signed_challenge)?;
        // Resolve the historical signer only after the exact submitted
        // envelope has been recovered from durable state. The challenge
        // cannot self-select a retired audit key and policy.
        let recorded_challenge = self
            .challenges
            .get_challenge(challenge_id)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("challenge is not recorded".to_owned())
            })?;
        if challenge_envelope_sha256 != recorded_challenge.challenge_envelope_sha256 {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        let audit_authority = match &signed_challenge.body.authorization {
            FindingChallengeAuthorization::VenueAudit(audit) => {
                let historical_policy = self
                    .filings
                    .audit_policy_for_epoch(&audit.audit_epoch_envelope_sha256)
                    .map_err(ChallengeCoordinatorError::FilingResolver)?
                    .ok_or(ChallengeCoordinatorError::UnknownAuditAuthorityPolicy)?;
                self.require_live_role(
                    &historical_policy,
                    signed_challenge.body.filed_at,
                    now,
                    "historical audit",
                )?
            }
            FindingChallengeAuthorization::BuyerSubmission(_) => self
                .pins
                .audit_authority
                .key()
                .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("audit"))?,
        };
        verify_signed_challenge(signed_challenge, &audit_authority)
            .map_err(|error| ChallengeCoordinatorError::ChallengeEnvelope(error.to_string()))?;
        let admission = self.resolve_admission(&signed_challenge.body, now)?;
        if admission.body.backing_allocation_id != identity.allocation_id {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "backing_allocation_id",
            ));
        }
        if outcome.body.challenge_envelope_sha256 != challenge_envelope_sha256 {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        // The outcome adjudicates exactly one challenge: the one whose
        // signed envelope digest it embeds. The durable row for the
        // challenge being upheld carries that digest, so an outcome
        // presented beside any other challenge id sanctions nothing, even
        // when both challenges target the same finding and listing.
        let presented_outcome_envelope_sha256 = self.envelope_digest(outcome)?;
        if recorded_challenge.outcome_envelope_sha256.as_deref()
            != Some(presented_outcome_envelope_sha256.as_str())
        {
            return Err(ChallengeCoordinatorError::OutcomeBinding);
        }
        // Every exposure figure behind the penalty is read against one
        // allocation, and it has to be the one this liability's vault is
        // charged to. Facts naming another allocation would size the
        // slash from a different seller's open encumbrances, so they are
        // refused here, before anything durable is written.
        if collateral.bond_snapshot.body.allocation_id != identity.allocation_id {
            return Err(ChallengeCoordinatorError::CollateralAllocation);
        }
        let snapshot = &collateral.bond_snapshot.body;
        if snapshot.chain_id != identity.chain_id
            || snapshot.vault_contract != identity.vault_contract
            || snapshot.vault_id != identity.vault_id
        {
            return Err(ChallengeCoordinatorError::CollateralSnapshot(
                "snapshot does not name this liability's vault",
            ));
        }
        let terms_envelope_sha256 = self.envelope_digest(terms)?;
        if terms_envelope_sha256 != signed_challenge.body.terms_envelope_sha256 {
            return Err(ChallengeCoordinatorError::TermsBinding(
                "terms_envelope_sha256",
            ));
        }
        let claim_deadline = self.require_claim_window(terms, identity, now)?;
        if terms.body.appeal_window_secs < MIN_APPEAL_WINDOW_SECS {
            return Err(ChallengeCoordinatorError::TermsBinding(
                "appeal_window_secs",
            ));
        }
        let appeal_terms_envelope_sha256 = terms_envelope_sha256.clone();
        Self::require_signed_base_stake(terms, collateral)?;
        let signed_stake = &terms.body.backing_requirement.base_finding_stake;
        if sanction_case.body.listing_id != identity.listing_id {
            return Err(ChallengeCoordinatorError::GovernanceBinding("listing_id"));
        }
        self.require_pinned_governance(governance, sanction_case, None, now)?;
        if self.envelope_digest(governance.fee_schedule)?
            != admission.body.fee_schedule_envelope_sha256
        {
            return Err(ChallengeCoordinatorError::GovernanceBinding(
                "fee_schedule_envelope_sha256",
            ));
        }
        let listing_requirement = Self::listing_bond_requirement(governance.fee_schedule)?;
        self.require_live_role(&self.penalty_pin, now, now, "penalty")?;
        let authoritative_claims = self
            .purchases
            .list_settled_purchase_keys_at_or_below(
                identity.listing_id,
                identity.allocation_id,
                cutoff_slot,
            )
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?;
        let mut supplied_claims = claim_candidates.to_vec();
        supplied_claims.sort();
        supplied_claims.dedup();
        if supplied_claims != authoritative_claims {
            return Err(ChallengeCoordinatorError::ClaimSetMismatch);
        }
        self.require_purchase_authority_for_candidates(identity, &authoritative_claims, now)?;
        self.require_impairable_collateral(collateral, now)?;
        let signed_calculation = outcome
            .body
            .penalty_calculation
            .as_ref()
            .ok_or(ChallengeCoordinatorError::PenaltyCalculationMismatch)?;
        let live_allocated_collateral = self.authenticated_live_collateral(collateral, now)?;
        if signed_calculation.base_finding_stake_units != signed_stake.units
            || signed_calculation.listing_required_amount_units != listing_requirement.units
            || signed_calculation.penalty_amount.currency != signed_stake.currency
            || listing_requirement.currency != signed_stake.currency
            || signed_calculation.penalty_amount.units > live_allocated_collateral
        {
            return Err(ChallengeCoordinatorError::PenaltyCalculationMismatch);
        }
        let defect_key = derive_defect_key(identity.finding_id);
        let liability_key = derive_liability_key(&defect_key, &self.venue_id, identity);
        let seller_hex = terms.body.seller.to_hex();
        self.challenges
            .open_liability(&FindingLiabilityInput {
                liability_key: &liability_key,
                defect_key: &defect_key,
                finding_id: identity.finding_id,
                listing_id: identity.listing_id,
                allocation_id: identity.allocation_id,
                seller_hex: &seller_hex,
                venue_id: &self.venue_id,
                chain_id: identity.chain_id,
                vault_contract: identity.vault_contract,
                vault_id: identity.vault_id,
                opened_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        self.challenges
            .uphold_liability(
                &liability_key,
                challenge_id,
                cutoff_slot,
                claim_deadline,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        // Re-enumerate after the upheld transaction raised the sales block,
        // and prove closure in the same SQLite snapshot as that enumeration.
        // A reservation settling across the earlier pure checks is therefore
        // either still open here or included in the immutable claim set.
        let authoritative_claims = self
            .purchases
            .closed_settled_purchase_keys_at_or_below(
                identity.listing_id,
                identity.allocation_id,
                cutoff_slot,
            )
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::ClaimWindowOpen)?;
        if supplied_claims != authoritative_claims {
            return Err(ChallengeCoordinatorError::ClaimSetMismatch);
        }
        self.require_purchase_authority_for_candidates(identity, &authoritative_claims, now)?;
        // The deadline the head froze when the window opened governs, not
        // the one this call just derived: a retry reads the instant harmed
        // buyers were promised rather than one measured from its own
        // clock, so no later attempt can shorten the window it resumes.
        let frozen = self
            .challenges
            .get_liability(&liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore(
                    "liability head is not recorded".to_owned(),
                )
            })?;
        match frozen.claim_deadline {
            Some(deadline) if now >= deadline => {}
            _ => return Err(ChallengeCoordinatorError::ClaimWindowOpen),
        }

        let sealed = self.seal_claim_snapshot(
            &liability_key,
            identity,
            cutoff_slot,
            &authoritative_claims,
            collateral,
            &signed_calculation.penalty_amount,
            &admission.body.community_fund_destination,
            now,
        )?;

        self.challenges
            .record_governance_case(&FindingGovernanceCaseInput {
                case_id: &sanction_case.body.case_id,
                finding_id: identity.finding_id,
                listing_id: identity.listing_id,
                liability_key: &liability_key,
                case_kind: FindingGovernanceCaseKind::Sanction,
                case_state: case_state_name(sanction_case),
                appeal_of_case_id: None,
                supersedes_case_id: None,
                recorded_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        let hold = self.mint_penalty(
            FindingPenaltyBranch::PendingAppeal,
            governance,
            sanction_case,
            None,
            &sealed.distribution.slash,
            outcome,
            &sanction_case.body.case_id,
            None,
            now,
            now,
        )?;

        self.challenges
            .begin_appeal_window(
                &liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                &appeal_terms_envelope_sha256,
                terms.body.appeal_window_secs,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;

        Ok(UpheldLiability {
            liability_key,
            sealed,
            sanction_case_id: sanction_case.body.case_id.clone(),
            hold,
        })
    }

    /// Close the appeal window.
    ///
    /// A timely successful appeal evaluates the reverse-slash branch and
    /// drives the liability to `reversed_before_impairment`; nothing was
    /// impaired, so nothing has to be undone. Appeal finality with no
    /// reversal evaluates the impairment branch, signs the enforcement
    /// instruction, fences every domain-keyed effect intent, and moves the
    /// liability to `finalizing` with publication pending. Anything else
    /// quarantines: an open, escalated, unresolved, or unavailable appeal
    /// is not a denial, and treating it as one would slash a seller whose
    /// appeal was still live.
    ///
    /// Fencing order. Every intent is persisted before the liability
    /// enters `finalizing`, and nothing is dispatched until it does, so no
    /// external effect can precede its own durable intent. The store
    /// exposes one intent per call rather than a batch, so a crash mid-way
    /// leaves a prefix of pending intents and the liability still in
    /// `pending_appeal`; the replay re-records each intent identically and
    /// continues, because an identical retry reconciles and a conflicting
    /// one rejects.
    ///
    /// Authority. Nothing about the target is taken from the caller, and
    /// neither is finality. The durable head is the only authority on
    /// which finding, listing, allocation, and vault this liability may
    /// impair, the only outcome that may authorize it is the exact
    /// envelope the store recorded for the challenge that upheld it, and
    /// the appeal window is proved closed against the durable case index
    /// rather than asserted by naming a disposition.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_appeal(
        &self,
        liability_key: &str,
        outcome: &SignedFindingChallengeOutcome,
        identity: &FindingLiabilityIdentity<'_>,
        sealed: Option<&SealedClaimSnapshot>,
        governance: &FindingPenaltyGovernance<'_>,
        disposition: &AppealDisposition<'_>,
        sanction_case_id: &str,
        hold: &FindingPenaltyOutcome,
        bond_snapshot_envelope_sha256: &str,
        now: u64,
    ) -> Result<AppealResolution, ChallengeCoordinatorError> {
        let record = self
            .challenges
            .get_liability(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore("liability is not recorded".to_owned())
            })?;
        let challenge_id = record
            .upheld_challenge_id
            .as_deref()
            .ok_or(ChallengeCoordinatorError::LiabilityState("upheld"))?;
        self.require_recorded_outcome_signature(challenge_id, outcome, now)?;
        self.require_identity_matches_head(liability_key, identity, &record)?;
        self.require_outcome_upheld_this_liability(outcome, &record)?;

        match disposition {
            AppealDisposition::Unresolved { reason } => {
                let sealed = sealed.ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
                self.require_sealed_matches_store(liability_key, sealed)?;
                self.challenges
                    .set_liability_quarantine(liability_key, true, now)
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(AppealResolution::Quarantined {
                    reason: (*reason).to_owned(),
                })
            }
            AppealDisposition::Successful {
                appeal_case,
                appeal_case_id,
            } => {
                let sealed = sealed.ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
                self.require_sealed_matches_store(liability_key, sealed)?;
                self.require_timely_appeal(&record, appeal_case, appeal_case_id)?;
                // The reversal is minted before the case is indexed. A
                // recorded appeal stamps the sanction superseded, and the
                // index admits exactly one supersession per case, so an
                // appeal that cannot authenticate must leave no head
                // behind: otherwise a malformed filing would permanently
                // consume the supersession a legitimate appeal needs.
                // Minting moves nothing on its own; it authenticates the
                // filing and signs, which is why it can run first.
                let reversal = self.mint_penalty(
                    FindingPenaltyBranch::SuccessfulAppeal,
                    governance,
                    appeal_case,
                    Some(&hold.penalty),
                    &sealed.distribution.slash,
                    outcome,
                    sanction_case_id,
                    Some(&hold.evaluation.penalty_id),
                    now,
                    now,
                )?;
                self.challenges
                    .record_governance_case(&FindingGovernanceCaseInput {
                        case_id: appeal_case_id,
                        finding_id: &record.finding_id,
                        listing_id: &record.listing_id,
                        liability_key,
                        case_kind: FindingGovernanceCaseKind::Appeal,
                        case_state: case_state_name(appeal_case),
                        appeal_of_case_id: Some(sanction_case_id),
                        supersedes_case_id: Some(sanction_case_id),
                        recorded_at: now,
                    })
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                self.challenges
                    .reverse_liability_before_impairment(
                        liability_key,
                        FindingLiabilityState::PendingAppeal,
                        now,
                    )
                    .map_err(|error| {
                        ChallengeCoordinatorError::ChallengeStore(error.to_string())
                    })?;
                Ok(AppealResolution::ReversedBeforeImpairment {
                    reversal: Box::new(reversal),
                })
            }
            AppealDisposition::Final { sanction_case } => {
                if record.state == FindingLiabilityState::Finalizing {
                    return self.recover_finalizing_authorization(
                        &record,
                        outcome,
                        sanction_case_id,
                        now,
                    );
                }
                let sealed = sealed.ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
                self.require_sealed_matches_store(liability_key, sealed)?;
                if record.state != FindingLiabilityState::PendingAppeal {
                    return Err(ChallengeCoordinatorError::LiabilityState("pending_appeal"));
                }
                self.require_current_role(
                    &self.status_feed_operator.authority,
                    now,
                    now,
                    "status feed operator",
                )?;
                self.require_live_role(&self.finalization_pin, now, now, "finalization")?;
                self.require_appeal_window_closed(&record, sanction_case, sanction_case_id, now)?;
                let penalty_issued_at = record
                    .appeal_deadline
                    .and_then(|deadline| deadline.checked_add(1))
                    .ok_or(ChallengeCoordinatorError::AppealNotFinal(
                        "appeal deadline has no representable successor",
                    ))?
                    .max(self.penalty_pin.valid_from);
                let slash = self.mint_penalty(
                    FindingPenaltyBranch::AppealFinalImpairment,
                    governance,
                    sanction_case,
                    Some(&hold.penalty),
                    &sealed.distribution.slash,
                    outcome,
                    sanction_case_id,
                    Some(&hold.evaluation.penalty_id),
                    penalty_issued_at,
                    now,
                )?;
                self.finalize_enforcement(
                    &record,
                    outcome,
                    sealed,
                    &slash,
                    sanction_case_id,
                    &hold.evaluation.penalty_id,
                    governance.admission,
                    governance.local_operator_id,
                    bond_snapshot_envelope_sha256,
                    now,
                )
            }
        }
    }
}
