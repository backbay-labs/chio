// Read-only coordinator accessors kept separate from lifecycle transitions.

impl FindingChallengeCoordinator {
        /// Serving identity shared by the coordinator's durable stores.
        #[must_use]
        pub fn mutation_fence(&self) -> StoreMutationFence {
            self.challenges.mutation_fence()
        }
    
        /// Read one challenge through the same durable store used by lifecycle
        /// transitions. The HTTP layer applies caller authorization before
        /// exposing this record.
        pub fn challenge_record(
            &self,
            challenge_id: &str,
        ) -> Result<Option<chio_store_sqlite::FindingChallengeRecord>, ChallengeCoordinatorError> {
            self.challenges
                .get_challenge(challenge_id)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))
        }
    
        /// Read the exact signed outcome retained for an authenticated challenge.
        pub fn challenge_outcome(
            &self,
            outcome_envelope_sha256: &str,
        ) -> Result<Option<chio_store_sqlite::FindingChallengeOutcomeRecord>, ChallengeCoordinatorError>
        {
            self.challenges
                .get_outcome_envelope(outcome_envelope_sha256)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))
        }

        /// Read the exact signed filing envelope retained atomically with a
        /// challenge. Legacy terminal rows may have no retained envelope.
        pub fn challenge_submission(
            &self,
            challenge_id: &str,
        ) -> Result<Option<chio_store_sqlite::FindingChallengeSubmissionEnvelopeRecord>, ChallengeCoordinatorError>
        {
            self.challenges
                .get_challenge_submission(challenge_id)
                .map_err(|error| ChallengeCoordinatorError::ChallengeStore(error.to_string()))
        }
    
        /// Exact validated market configuration this coordinator enforces.
        #[must_use]
        pub const fn market_config(&self) -> &FindingMarketConfig {
            &self.market_config
        }
    
        /// Resolver used by read paths to recheck current authority standing.
        pub(crate) fn authority_status_resolver(&self) -> Arc<dyn FindingAuthorityStatusResolver> {
            Arc::clone(&self.authority_status)
        }
}
