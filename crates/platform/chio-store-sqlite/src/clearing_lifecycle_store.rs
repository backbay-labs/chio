use std::sync::Arc;

use chio_core::economic_continuity::{EconomicResourceKeyV1, VerifiedEconomicStateBatchAdvance};
use chio_core::StoreMutationFence;
use chio_credit::clearing::{
    verify_clearing_lifecycle_replay_authority_verification_with_outcome,
    verify_clearing_lifecycle_replay_with_outcome, ClearingDisputeWindowResolver, ClearingError,
    ClearingLifecycleAuthorityPinsV1, ClearingLifecycleAuthorityVerificationV1,
    ClearingLifecycleAuthorityVerifier, ClearingLifecycleBatchVerifier,
    ClearingLifecycleProofResolver, ClearingLifecycleReplayV1, ClearingRoundTransitionProofV1,
    ClearingSettlementOutcomeVerifier, CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND,
    CLEARING_ROUND_RESOURCE_FAMILY,
};
use chio_federation::frost::FrostArtifactTrustStore;

use crate::economic_state_cache::EconomicStageAdmissionCheckpoint;
use crate::{
    EconomicStateCacheError, EconomicStateStageDescriptor, EconomicStateStageRecord,
    SqliteEconomicStateCache,
};

#[derive(Debug, thiserror::Error)]
pub enum ClearingLifecycleStoreError {
    #[error(transparent)]
    Cache(#[from] EconomicStateCacheError),
    #[error(transparent)]
    Clearing(#[from] ClearingError),
}

#[derive(Clone)]
pub struct SqliteClearingLifecycleStore {
    cache: SqliteEconomicStateCache,
    pins: ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<Arc<FrostArtifactTrustStore>>,
    dispute_resolver: Arc<dyn ClearingDisputeWindowResolver>,
    settlement_outcome_verifier: Option<Arc<dyn ClearingSettlementOutcomeVerifier>>,
}

impl SqliteClearingLifecycleStore {
    pub fn new(
        cache: SqliteEconomicStateCache,
        pins: ClearingLifecycleAuthorityPinsV1,
        frost_trust: Option<Arc<FrostArtifactTrustStore>>,
        dispute_resolver: Arc<dyn ClearingDisputeWindowResolver>,
    ) -> Result<Self, ClearingLifecycleStoreError> {
        pins.validate()?;
        Ok(Self {
            cache,
            pins,
            frost_trust,
            dispute_resolver,
            settlement_outcome_verifier: None,
        })
    }

    #[must_use]
    pub fn with_settlement_outcome_verifier(
        mut self,
        verifier: Arc<dyn ClearingSettlementOutcomeVerifier>,
    ) -> Self {
        self.settlement_outcome_verifier = Some(verifier);
        self
    }

    pub fn stage(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        replay: &ClearingLifecycleReplayV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, ClearingLifecycleStoreError> {
        verify_clearing_lifecycle_replay_with_outcome(
            advance.current(),
            advance.batch(),
            replay,
            &self.pins,
            self.frost_trust.as_deref(),
            Some(self.dispute_resolver.as_ref()),
            self.settlement_outcome_verifier.as_deref(),
        )?;
        if replay.authorized_at_unix_ms() > trusted_now_unix_ms {
            return Err(ClearingError::AuthorityVerification.into());
        }
        let proof_digest = replay.proof_digest()?;
        let descriptor = EconomicStateStageDescriptor::new(
            CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND,
            &proof_digest,
            replay,
        )?;
        let checkpoint = replay
            .admission_checkpoint()
            .map(
                |(store_id, sequence, digest)| EconomicStageAdmissionCheckpoint {
                    store_id,
                    sequence,
                    digest,
                },
            );
        let record = self.cache.stage_clearing_lifecycle_batch(
            advance,
            descriptor,
            checkpoint,
            active_fence,
            trusted_now_unix_ms,
        )?;
        Ok(record)
    }

    #[must_use]
    pub fn recovery_verifier(self: &Arc<Self>) -> ClearingLifecycleBatchVerifier {
        ClearingLifecycleBatchVerifier::new(self.clone(), self.clone())
    }

    fn load_replay(
        &self,
        proof_digest: &str,
    ) -> Result<(EconomicStateStageRecord, ClearingLifecycleReplayV1), ClearingLifecycleStoreError>
    {
        let record = self
            .cache
            .load_stage_by_descriptor(CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND, proof_digest)?
            .ok_or(EconomicStateCacheError::NotFound)?;
        let descriptor = record
            .descriptor()
            .ok_or(EconomicStateCacheError::Conflict)?;
        if descriptor.kind() != CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND
            || descriptor.key() != proof_digest
        {
            return Err(EconomicStateCacheError::Conflict.into());
        }
        let replay = descriptor.decode::<ClearingLifecycleReplayV1>()?;
        if replay.proof_digest()? != proof_digest {
            return Err(EconomicStateCacheError::Conflict.into());
        }
        Ok((record, replay))
    }
}

impl ClearingLifecycleProofResolver for SqliteClearingLifecycleStore {
    fn resolve(&self, proof_digest: &str) -> Result<ClearingRoundTransitionProofV1, ClearingError> {
        self.load_replay(proof_digest)
            .map(|(_, replay)| replay.proof)
            .map_err(|_| ClearingError::AuthorityVerification)
    }
}

impl ClearingLifecycleAuthorityVerifier for SqliteClearingLifecycleStore {
    fn verify(
        &self,
        proof: &ClearingRoundTransitionProofV1,
    ) -> Result<ClearingLifecycleAuthorityVerificationV1, ClearingError> {
        let proof_digest = proof.digest()?;
        let (record, replay) = self
            .load_replay(&proof_digest)
            .map_err(|_| ClearingError::AuthorityVerification)?;
        if replay.proof != *proof {
            return Err(ClearingError::AuthorityVerification);
        }
        let round_key = EconomicResourceKeyV1 {
            resource_family: CLEARING_ROUND_RESOURCE_FAMILY.to_owned(),
            scope_id: proof.governance_scope_id.clone(),
            resource_id: proof.round_id.clone(),
        };
        let source_round_head = record
            .base_view()
            .head(&round_key)
            .ok_or(ClearingError::IncompleteLifecycleProjection)?;
        verify_clearing_lifecycle_replay_authority_verification_with_outcome(
            source_round_head,
            &replay,
            &self.pins,
            self.frost_trust.as_deref(),
            Some(self.dispute_resolver.as_ref()),
            self.settlement_outcome_verifier.as_deref(),
        )
    }
}
