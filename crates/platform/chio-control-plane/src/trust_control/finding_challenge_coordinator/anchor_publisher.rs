use super::*;

pub(super) struct AuthenticatedAnchorPublisher {
    policy: FindingPenaltyAuthorityPolicy,
    status: SignedFindingAuthorityStatus,
    checkpoint_publication: SignedFindingAnchorCheckpointPublication,
    status_authority: PublicKey,
    trusted_now_secs: u64,
}

impl AuthenticatedAnchorPublisher {
    pub(super) fn evidence(&self) -> FindingAnchorPublisherEvidence<'_> {
        FindingAnchorPublisherEvidence {
            retained_policy: &self.policy,
            signed_status: &self.status,
            signed_checkpoint_publication: &self.checkpoint_publication,
            status_authority: &self.status_authority,
            max_status_age_secs: MAX_REVOCATION_STATUS_AGE_SECS,
            trusted_now_secs: self.trusted_now_secs,
        }
    }
}

impl FindingChallengeCoordinator {
    pub(super) fn authenticate_anchor_publisher(
        &self,
        proof: &AnchorInclusionProof,
        now: u64,
    ) -> Result<AuthenticatedAnchorPublisher, ChallengeCoordinatorError> {
        let (_, status) = self.resolve_live_role(
            &self.pins.anchor_publisher,
            proof.checkpoint_statement.issued_at,
            now,
            "anchor publisher",
        )?;
        let policy = settlement_penalty_authority_policy(&self.pins.anchor_publisher)?;
        let checkpoint_publication = self
            .authority_status
            .checkpoint_publication(proof, now)
            .map_err(|error| {
                ChallengeCoordinatorError::Settlement(format!(
                    "anchor checkpoint publication could not be resolved: {error}"
                ))
            })?;
        let status_authority = self
            .pins
            .authority_status
            .key()
            .map_err(|_| ChallengeCoordinatorError::AuthorityPinMismatch("authority status"))?;
        Ok(AuthenticatedAnchorPublisher {
            policy,
            status,
            checkpoint_publication,
            status_authority,
            trusted_now_secs: now,
        })
    }
}
