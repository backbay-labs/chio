//! Durable finalization authorization checks.

use super::*;

impl FindingChallengeCoordinator {
    /// Bind a still-pending root intent to the concrete proof this finalize
    /// attempt prepared. The generic liability and penalty commitment is
    /// checked first, so a mismatched intent cannot be poisoned with a
    /// binding that belongs elsewhere.
    pub(super) fn bind_enforcement_root(
        &self,
        liability_key: &str,
        verified: &VerifiedFindingEnforcement,
        planned: &chio_settle::FindingImpairmentIntent,
        now: u64,
    ) -> Result<(), ChallengeCoordinatorError> {
        let root = self
            .challenges
            .get_effect_intent(verified.root_intent_id())
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or(ChallengeCoordinatorError::EffectIntentUnfenced)?;
        let expected = sha256_hex(
            root_intent_commitment(
                liability_key,
                &verified.enforcement().penalty_envelope_sha256,
            )
            .as_bytes(),
        );
        if root.kind != FindingEffectIntentKind::RootIntent
            || root.liability_key.as_deref() != Some(liability_key)
            || root.intent_digest != expected
        {
            return Err(ChallengeCoordinatorError::EnforcementRootUnconfirmed(
                "the named root intent does not fence this liability and penalty",
            ));
        }
        self.challenges
            .bind_effect_root(
                verified.root_intent_id(),
                liability_key,
                &planned.merkle_root,
                &planned.evidence_hash,
                now,
            )
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?;
        Ok(())
    }

    /// Authenticate one retained enforcement under the exact historical
    /// finalization policy its signed body commits. The independently signed
    /// lifecycle status keeps body fields from self-authorizing a signer.
    pub(super) fn require_enforcement_signature(
        &self,
        enforcement: &SignedFindingChallengeEnforcement,
        historical_pin: &FindingAuthorityPin,
        now: u64,
    ) -> Result<(PublicKey, SignedFindingAuthorityStatus), ChallengeCoordinatorError> {
        enforcement
            .body
            .validate()
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        let body = &enforcement.body;
        if body.finalization_authority_id != historical_pin.authority_id
            || body.finalization_key.to_hex() != historical_pin.key_hex
            || body.finalization_key_epoch != historical_pin.key_epoch
            || body.finalization_valid_from != historical_pin.valid_from
            || body.finalization_valid_until != historical_pin.valid_until
            || body.finalization_revocation_status_ref != historical_pin.revocation_status_ref
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "enforcement finalization authority does not match retained governance policy"
                    .to_owned(),
            ));
        }
        let (authority, status) = self.resolve_live_role(
            historical_pin,
            body.finalized_at,
            now,
            "historical finalization",
        )?;
        verify_pinned_envelope(enforcement, &authority, "finding challenge enforcement")
            .map_err(|error| ChallengeCoordinatorError::Settlement(error.to_string()))?;
        Ok((authority, status))
    }

    pub(super) fn load_retained_finalizing_authorization(
        &self,
        liability_key: &str,
    ) -> Result<(RetainedAuthorizedImpairment, u64), ChallengeCoordinatorError> {
        let stored = self
            .challenges
            .get_finalizing_authorization(liability_key)
            .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))?
            .ok_or_else(|| {
                ChallengeCoordinatorError::ChallengeStore(
                    "finalizing liability has no retained authorization".to_owned(),
                )
            })?;
        if sha256_hex(&stored.authorization_json) != stored.authorization_sha256 {
            return Err(ChallengeCoordinatorError::ChallengeStore(
                "retained finalizing authorization digest mismatch".to_owned(),
            ));
        }
        let retained: RetainedAuthorizedImpairment =
            serde_json::from_slice(&stored.authorization_json).map_err(|error| {
                ChallengeCoordinatorError::ChallengeStore(format!(
                    "retained finalizing authorization is invalid: {error}"
                ))
            })?;
        let canonical =
            canonical_json_bytes(&retained).map_err(|_| ChallengeCoordinatorError::Canonical)?;
        if canonical != stored.authorization_json {
            return Err(ChallengeCoordinatorError::ChallengeStore(
                "retained finalizing authorization is not canonical".to_owned(),
            ));
        }
        Ok((retained, stored.recorded_at))
    }

    /// Bind a finalization attempt to the immutable authorization retained
    /// with the state transition. Only an authenticated pre-dispatch snapshot
    /// refresh may change the finalization envelope.
    pub(super) fn require_retained_finalizing_authorization(
        &self,
        liability_key: &str,
        enforcement: &SignedFindingChallengeEnforcement,
        penalty: &SignedOpenMarketPenalty,
        allow_snapshot_refresh: bool,
    ) -> Result<RetainedAuthorizedImpairment, ChallengeCoordinatorError> {
        let (retained, _) = self.load_retained_finalizing_authorization(liability_key)?;
        if self.envelope_digest(penalty)? != self.envelope_digest(&retained.slash.penalty)? {
            return Err(ChallengeCoordinatorError::Settlement(
                "presented penalty is not the retained finalizing authorization".to_owned(),
            ));
        }
        if self.envelope_digest(enforcement)? == self.envelope_digest(&retained.enforcement)? {
            return Ok(retained);
        }
        if !allow_snapshot_refresh {
            return Err(ChallengeCoordinatorError::Settlement(
                "presented enforcement is not the retained finalizing authorization".to_owned(),
            ));
        }

        let retained_body = &retained.enforcement.body;
        let body = &enforcement.body;
        if body.bond_snapshot_envelope_sha256 == retained_body.bond_snapshot_envelope_sha256
            || body.finalized_at <= retained_body.finalized_at
            || body.finalization_authority_id != self.finalization_pin.authority_id
            || body.finalization_key != self.finalization_authority.public_key()
            || body.finalization_key_epoch != self.finalization_pin.key_epoch
            || body.finalization_valid_from != self.finalization_pin.valid_from
            || body.finalization_valid_until != self.finalization_pin.valid_until
            || body.finalization_revocation_status_ref
                != self.finalization_pin.revocation_status_ref
        {
            return Err(ChallengeCoordinatorError::Settlement(
                "snapshot refresh is outside the retained authorization".to_owned(),
            ));
        }
        let mut normalized = body.clone();
        normalized.enforcement_id = retained_body.enforcement_id.clone();
        normalized.bond_snapshot_envelope_sha256 =
            retained_body.bond_snapshot_envelope_sha256.clone();
        normalized.finalization_authority_id = retained_body.finalization_authority_id.clone();
        normalized.finalization_key = retained_body.finalization_key.clone();
        normalized.finalization_key_epoch = retained_body.finalization_key_epoch;
        normalized.finalization_valid_from = retained_body.finalization_valid_from;
        normalized.finalization_valid_until = retained_body.finalization_valid_until;
        normalized.finalization_revocation_status_ref =
            retained_body.finalization_revocation_status_ref.clone();
        normalized.finalized_at = retained_body.finalized_at;
        if normalized != *retained_body {
            return Err(ChallengeCoordinatorError::Settlement(
                "snapshot refresh changed retained enforcement semantics".to_owned(),
            ));
        }
        Ok(retained)
    }
}
