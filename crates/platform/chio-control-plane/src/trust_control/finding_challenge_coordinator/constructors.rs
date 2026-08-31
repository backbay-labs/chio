// Local-key compatibility and custody-backed coordinator constructors.

impl FindingChallengeCoordinator {
    /// Build over the durable stores while checking all configured role pins.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenges: SqliteFindingChallengeStore,
        purchases: SqliteFindingPurchaseStore,
        status: SqliteFindingStatusStore,
        config: &FindingMarketConfig,
        evaluator_authority: Keypair,
        finalization_authority: Keypair,
        penalty_authority: Keypair,
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        rail: Arc<dyn FindingRailObserver>,
        filings: Arc<dyn FindingFilingResolver>,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<Self, ChallengeCoordinatorError> {
        Self::new_with_status_commit_clock(
            challenges,
            purchases,
            status,
            config,
            evaluator_authority,
            finalization_authority,
            penalty_authority,
            authority_status,
            rail,
            filings,
            failed_challenge_disposition,
            Arc::new(SystemFindingStatusCommitClock),
        )
    }

    /// Build with local compatibility keys and an injected clock.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_status_commit_clock(
        challenges: SqliteFindingChallengeStore,
        purchases: SqliteFindingPurchaseStore,
        status: SqliteFindingStatusStore,
        config: &FindingMarketConfig,
        evaluator_authority: Keypair,
        finalization_authority: Keypair,
        penalty_authority: Keypair,
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        rail: Arc<dyn FindingRailObserver>,
        filings: Arc<dyn FindingFilingResolver>,
        failed_challenge_disposition: FindingDisputeLockDisposition,
        status_commit_clock: Arc<dyn FindingStatusCommitClock>,
    ) -> Result<Self, ChallengeCoordinatorError> {
        Self::new_with_signing_backends_and_status_commit_clock(
            challenges,
            purchases,
            status,
            config,
            Arc::new(Ed25519Backend::new(evaluator_authority)),
            Arc::new(Ed25519Backend::new(finalization_authority)),
            Arc::new(Ed25519Backend::new(penalty_authority)),
            authority_status,
            rail,
            filings,
            failed_challenge_disposition,
            status_commit_clock,
        )
    }

    /// Build with custody-backed signers and the production commit clock.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_signing_backends(
        challenges: SqliteFindingChallengeStore,
        purchases: SqliteFindingPurchaseStore,
        status: SqliteFindingStatusStore,
        config: &FindingMarketConfig,
        evaluator_authority: Arc<dyn SigningBackend>,
        finalization_authority: Arc<dyn SigningBackend>,
        penalty_authority: Arc<dyn SigningBackend>,
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        rail: Arc<dyn FindingRailObserver>,
        filings: Arc<dyn FindingFilingResolver>,
        failed_challenge_disposition: FindingDisputeLockDisposition,
    ) -> Result<Self, ChallengeCoordinatorError> {
        Self::new_with_signing_backends_and_status_commit_clock(
            challenges,
            purchases,
            status,
            config,
            evaluator_authority,
            finalization_authority,
            penalty_authority,
            authority_status,
            rail,
            filings,
            failed_challenge_disposition,
            Arc::new(SystemFindingStatusCommitClock),
        )
    }
}
