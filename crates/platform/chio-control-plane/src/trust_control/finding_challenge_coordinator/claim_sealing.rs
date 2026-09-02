// Penalty arithmetic, claim-snapshot sealing, and purchase standing.

impl FindingChallengeCoordinator {
    /// Compute the checked penalty calculation the outcome carries.
    ///
    /// The formula is predeclared and every member is recorded, so the
    /// penalty lane rechecks it rather than trusting one number. The open
    /// per-sale encumbrances come from the authoritative purchase store,
    /// never from the filing.
    fn checked_penalty_calculation(
        &self,
        collateral: &FindingCollateralFacts<'_>,
        listing_required_amount: &MonetaryAmount,
        now: u64,
    ) -> Result<FindingPenaltyCalculation, ChallengeCoordinatorError> {
        let live_allocated_collateral = self.authenticated_live_collateral(collateral, now)?;
        let open = self.outstanding_exposure(&collateral.bond_snapshot.body.allocation_id, now)?;
        let computed = collateral
            .base_finding_stake
            .units
            .checked_add(open)
            .ok_or_else(|| {
                ChallengeCoordinatorError::SlashArithmetic(
                    "computed exposure overflowed".to_owned(),
                )
            })?;
        let calculation = FindingPenaltyCalculation {
            base_finding_stake_units: collateral.base_finding_stake.units,
            open_per_sale_encumbrance_units: open,
            computed_exposure_units: computed,
            listing_required_amount_units: listing_required_amount.units,
            live_allocated_collateral_units: live_allocated_collateral,
            penalty_amount: MonetaryAmount {
                units: computed.min(live_allocated_collateral),
                currency: collateral.base_finding_stake.currency.clone(),
            },
        };
        Ok(calculation)
    }

    /// Derive, check, and seal the accounting the payout comes from.
    ///
    /// Candidate purchase keys are hints. Every figure that reaches the
    /// distribution is re-read from the authoritative purchase index and
    /// re-verified: the record must verify under the pinned purchase
    /// authority, name this liability's finding and listing, sit at or
    /// below the frozen cutoff on a slot that closed against a settled
    /// record, have charged its exposure to this liability's allocation,
    /// pay a destination that was admitted at capture, and be denominated
    /// in the bond currency. No caller-supplied amount or address
    /// survives.
    fn seal_claim_snapshot(
        &self,
        liability_key: &str,
        identity: &FindingLiabilityIdentity<'_>,
        cutoff_slot: u64,
        claim_candidates: &[String],
        collateral: &FindingCollateralFacts<'_>,
        expected_penalty: &MonetaryAmount,
        community_fund_destination: &str,
        now: u64,
    ) -> Result<SealedClaimSnapshot, ChallengeCoordinatorError> {
        let harms = self.verified_harms(
            identity,
            &collateral.base_finding_stake.currency,
            cutoff_slot,
            claim_candidates,
            now,
        )?;
        let total_realized_spend_units = harms
            .iter()
            .try_fold(0_u64, |total, harm| {
                total.checked_add(harm.realized_spend_units)
            })
            .ok_or_else(|| {
                ChallengeCoordinatorError::SlashArithmetic("verified harm overflowed".to_owned())
            })?;
        let live_allocated_collateral = self.authenticated_live_collateral(collateral, now)?;
        if expected_penalty.currency != collateral.base_finding_stake.currency
            || expected_penalty.units > live_allocated_collateral
        {
            return Err(ChallengeCoordinatorError::PenaltyCalculationMismatch);
        }
        let distribution =
            compute_frozen_slash_distribution(expected_penalty, community_fund_destination, &harms)
                .map_err(|error| ChallengeCoordinatorError::SlashArithmetic(error.to_string()))?;

        let snapshot_digest = snapshot_digest_of(&harms)?;
        let allocation_digest = allocation_digest_of(&distribution)?;
        self.challenges
            .seal_claim_snapshot(&FindingClaimSnapshotInput {
                liability_key,
                cutoff_slot,
                snapshot_digest: &snapshot_digest,
                allocation_digest: &allocation_digest,
                total_realized_spend_units,
                currency: &distribution.slash.currency,
                buyer_pool_units: distribution.buyer_pool_units,
                community_fund_units: distribution.community_fund_units,
                sealed_at: now,
            })
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(SealedClaimSnapshot {
            liability_key: liability_key.to_owned(),
            cutoff_slot,
            snapshot_digest,
            allocation_digest,
            total_realized_spend_units,
            distribution,
        })
    }

    /// Re-resolve every candidate purchase through the authoritative
    /// index and build the verified harm set.
    ///
    /// Two settled purchases can name one immutable destination, which the
    /// enforcement instruction forbids repeating, so harms sharing a
    /// destination are folded into one entry carrying the summed spend and
    /// the lowest purchase key. Folding rather than rejecting keeps a
    /// buyer who bought twice whole, and keying on the lowest purchase key
    /// keeps the remainder order deterministic.
    fn verified_harms(
        &self,
        identity: &FindingLiabilityIdentity<'_>,
        bond_currency: &str,
        cutoff_slot: u64,
        claim_candidates: &[String],
        now: u64,
    ) -> Result<Vec<VerifiedHarm>, ChallengeCoordinatorError> {
        let admitted = self
            .purchases
            .list_payout_destinations(identity.allocation_id)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?;
        let mut folded: std::collections::BTreeMap<String, VerifiedHarm> =
            std::collections::BTreeMap::new();
        let mut keys: Vec<&String> = claim_candidates.iter().collect();
        keys.sort();
        keys.dedup();
        for purchase_key in keys {
            let row = self
                .purchases
                .get_purchase_record(purchase_key)
                .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
                .ok_or_else(|| {
                    ChallengeCoordinatorError::UnknownPurchaseRecord(purchase_key.clone())
                })?;
            let signed: SignedFindingPurchaseRecord = serde_json::from_slice(&row.record_json)
                .map_err(|error| {
                    ChallengeCoordinatorError::ArtifactValidation(error.to_string())
                })?;
            self.verify_purchase_record_from_retained_admission(identity, &signed, now)?;
            let record: &FindingPurchaseRecord = &signed.body;
            if record.finding_id != identity.finding_id
                || record.listing_id != identity.listing_id
                || &record.purchase_key != purchase_key
            {
                return Err(ChallengeCoordinatorError::PurchaseOutsideCutoff(
                    purchase_key.clone(),
                ));
            }
            let slot = self
                .purchases
                .get_slot(&row.reservation_id)
                .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
                .ok_or_else(|| {
                    ChallengeCoordinatorError::PurchaseOutsideCutoff(purchase_key.clone())
                })?;
            if slot.listing_id != identity.listing_id || slot.slot_ordinal > cutoff_slot {
                return Err(ChallengeCoordinatorError::PurchaseOutsideCutoff(
                    purchase_key.clone(),
                ));
            }
            // The reservation's encumbrance is what charged this sale to a
            // vault, and a listing may be rebacked between sales. A record
            // whose exposure was booked against another allocation is not
            // this liability's harm: paying it here would take the money
            // from a seller who never sold it.
            let encumbrance = self
                .purchases
                .get_encumbrance(&row.reservation_id)
                .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
                .ok_or_else(|| {
                    ChallengeCoordinatorError::PurchaseOutsideAllocation(purchase_key.clone())
                })?;
            if encumbrance.allocation_id != identity.allocation_id {
                return Err(ChallengeCoordinatorError::PurchaseOutsideAllocation(
                    purchase_key.clone(),
                ));
            }
            if !admitted
                .iter()
                .any(|(_, destination)| destination == &record.payout_destination)
            {
                return Err(ChallengeCoordinatorError::UnadmittedPayoutDestination(
                    purchase_key.clone(),
                ));
            }
            // A verified harm carries bare units that the distribution
            // reads as bond currency, so the denomination has to be proven
            // here. Folding a spend attested in another currency would pay
            // it out unit for unit against collateral it never priced.
            if record.realized_spend.currency != bond_currency {
                return Err(ChallengeCoordinatorError::PurchaseCurrencyMismatch(
                    purchase_key.clone(),
                ));
            }
            let entry = folded
                .entry(record.payout_destination.clone())
                .or_insert_with(|| VerifiedHarm {
                    purchase_key: record.purchase_key.clone(),
                    destination: record.payout_destination.clone(),
                    realized_spend_units: 0,
                });
            if record.purchase_key < entry.purchase_key {
                entry.purchase_key = record.purchase_key.clone();
            }
            entry.realized_spend_units = entry
                .realized_spend_units
                .checked_add(record.realized_spend.units)
                .ok_or_else(|| {
                    ChallengeCoordinatorError::SlashArithmetic(
                        "folded realized spend overflowed".to_owned(),
                    )
                })?;
        }
        let mut harms: Vec<VerifiedHarm> = folded.into_values().collect();
        harms.sort_by(|left, right| left.purchase_key.cmp(&right.purchase_key));
        Ok(harms)
    }

    /// Authenticate every candidate purchase before the liability
    /// transaction blocks sales. The full listing, cutoff, allocation,
    /// and payout checks still run while sealing.
    fn require_purchase_authority_for_candidates(
        &self,
        identity: &FindingLiabilityIdentity<'_>,
        claim_candidates: &[String],
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let mut keys: Vec<&String> = claim_candidates.iter().collect();
        keys.sort();
        keys.dedup();
        for purchase_key in keys {
            let row = self
                .purchases
                .get_purchase_record(purchase_key)
                .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
                .ok_or_else(|| {
                    ChallengeCoordinatorError::UnknownPurchaseRecord(purchase_key.clone())
                })?;
            let signed: SignedFindingPurchaseRecord = serde_json::from_slice(&row.record_json)
                .map_err(|error| {
                    ChallengeCoordinatorError::ArtifactValidation(error.to_string())
                })?;
            self.verify_purchase_record_from_retained_admission(identity, &signed, now)?;
        }
        Ok(())
    }

    /// Authenticate purchase standing against both durable existence and
    /// the admission-pinned authority lifecycle before pure adjudication.
    /// A caller-supplied signed record is not standing merely because its
    /// signer can backdate `recorded_at`: the exact envelope must be the one
    /// the purchase authority retained when the sale settled.
    fn require_authoritative_purchase_standing(
        &self,
        admission: &SignedFindingAdmission,
        evidence: &FindingChallengeClassEvidence<'_>,
        now: u64,
    ) -> Result<Option<SignedFindingAuthorityStatus>, ChallengeCoordinatorError> {
        let signed = match evidence {
            FindingChallengeClassEvidence::EvidenceInvalid(evidence) => {
                evidence.purchase_standing.purchase_record
            }
            FindingChallengeClassEvidence::ReplayContradiction(evidence) => {
                evidence.purchase_standing.purchase_record
            }
            FindingChallengeClassEvidence::DigestMismatch(_) => return Ok(None),
        };
        let record = &signed.body;
        let stored = self
            .purchases
            .get_purchase_record(&record.purchase_key)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::UnknownPurchaseRecord(record.purchase_key.clone())
            })?;
        let presented_json =
            canonical_json_bytes(signed).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        if stored.record_json != presented_json
            || stored.record_sha256 != sha256_hex(&presented_json)
            || stored.recorded_at != record.recorded_at
        {
            return Err(ChallengeCoordinatorError::PurchaseStanding(
                "the supplied envelope is not the retained settled record".to_owned(),
            ));
        }
        if self.envelope_digest(admission)? != record.venue_admission_envelope_sha256 {
            return Err(ChallengeCoordinatorError::PurchaseStanding(
                "the retained record names another venue admission".to_owned(),
            ));
        }
        let policy = &admission.body.purchase_authority;
        policy
            .validate("purchase_authority")
            .map_err(|error| ChallengeCoordinatorError::PurchaseStanding(error.to_string()))?;
        let standing_pin = FindingAuthorityPin {
            authority_id: policy.authority_id.clone(),
            key_hex: policy.key.to_hex(),
            key_epoch: policy.key_epoch,
            valid_from: policy.valid_from,
            valid_until: policy.valid_until,
            revocation_status_ref: policy.revocation_status_ref.clone(),
        };
        let (purchase_authority, purchase_authority_status) =
            self.resolve_live_role(&standing_pin, record.recorded_at, now, "purchase standing")?;
        verify_signed_purchase_record(signed, &purchase_authority)
            .map_err(|error| ChallengeCoordinatorError::PurchaseStanding(error.to_string()))?;
        Ok(Some(purchase_authority_status))
    }

    /// Verify a historical purchase under the authority policy the venue
    /// authenticated for that exact sale. A later deployment rotation does
    /// not invalidate an earlier record, while the retained policy's own
    /// validity window and independently signed revocation status still
    /// fail closed.
    fn verify_purchase_record_from_retained_admission(
        &self,
        identity: &FindingLiabilityIdentity<'_>,
        signed: &SignedFindingPurchaseRecord,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let record = &signed.body;
        let admission = self
            .filings
            .admission_by_envelope_sha256(&record.venue_admission_envelope_sha256)
            .map_err(ChallengeCoordinatorError::FilingResolver)?
            .ok_or(ChallengeCoordinatorError::UnknownAdmission)?;
        if self.envelope_digest(&admission)? != record.venue_admission_envelope_sha256 {
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
        if admission.body.finding_id != record.finding_id
            || admission.body.listing_id != record.listing_id
            || admission.body.backing_allocation_id != identity.allocation_id
            || admission.body.backing_envelope_sha256 != record.seller_backing_envelope_sha256
        {
            return Err(ChallengeCoordinatorError::AdmissionBinding(
                "purchase_record",
            ));
        }
        let policy = &admission.body.purchase_authority;
        policy
            .validate("purchase_authority")
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))?;
        let retained_pin = FindingAuthorityPin {
            authority_id: policy.authority_id.clone(),
            key_hex: policy.key.to_hex(),
            key_epoch: policy.key_epoch,
            valid_from: policy.valid_from,
            valid_until: policy.valid_until,
            revocation_status_ref: policy.revocation_status_ref.clone(),
        };
        let purchase_authority =
            self.require_live_role(&retained_pin, record.recorded_at, now, "retained purchase")?;
        verify_signed_purchase_record(signed, &purchase_authority)
            .map_err(|error| ChallengeCoordinatorError::ArtifactValidation(error.to_string()))
    }

    /// Require the carried accounting to be exactly what the store
    /// sealed. The sealed row is the fence: a caller cannot substitute a
    /// different distribution for the one the claim window produced.
    fn require_sealed_matches_store(
        &self,
        liability_key: &str,
        sealed: &SealedClaimSnapshot,
    ) -> Result<(), ChallengeCoordinatorError> {
        let record = self
            .challenges
            .get_claim_snapshot(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::SealedClaimMismatch)?;
        let allocation_digest = allocation_digest_of(&sealed.distribution)?;
        if record.snapshot_digest != sealed.snapshot_digest
            || record.allocation_digest != sealed.allocation_digest
            || record.allocation_digest != allocation_digest
            || record.cutoff_slot != sealed.cutoff_slot
            || record.total_realized_spend_units != sealed.total_realized_spend_units
            || record.buyer_pool_units != sealed.distribution.buyer_pool_units
            || record.community_fund_units != sealed.distribution.community_fund_units
        {
            return Err(ChallengeCoordinatorError::SealedClaimMismatch);
        }
        Ok(())
    }
}
