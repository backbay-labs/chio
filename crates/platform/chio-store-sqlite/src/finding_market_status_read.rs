use super::{
    require_verified_live_status_tx, sqlite_error, FindingMarketStoreError,
    SqliteFindingMarketStore,
};

impl SqliteFindingMarketStore {
    /// Require an exact current-floor live Finding status under the
    /// governance-pinned feed, operator authorization, and configured
    /// signed-epoch age ceiling. Public discovery uses this read seam so it
    /// never advertises an admission that the atomic purchase gate would
    /// reject.
    pub fn require_verified_live_status(
        &self,
        feed_id: &str,
        finding_id: &str,
        operator_authorization_sha256: &str,
        operator_status_observed_at: u64,
        trusted_now: u64,
        max_epoch_age_secs: u64,
    ) -> Result<(), FindingMarketStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        require_verified_live_status_tx(
            &transaction,
            feed_id,
            finding_id,
            operator_authorization_sha256,
            operator_status_observed_at,
            trusted_now,
            max_epoch_age_secs,
        )?;
        transaction.commit().map_err(sqlite_error)
    }
}
