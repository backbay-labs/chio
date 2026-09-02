use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::{
    admission_error, require_verified_live_status_tx, sqlite_error, verify_active_owner,
    FindingMarketStoreError, SqliteFindingMarketStore,
};

impl SqliteFindingMarketStore {
    /// Open a read transaction on the read-only companion connection.
    ///
    /// The companion trails the writer by at most one in-flight
    /// transaction, so only surfaces that re-verify on the serving-owner
    /// connection or deliberately under-advertise may use it.
    fn begin_companion_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingMarketStoreError> {
        // Read the anchor before the snapshot it will be proved against.
        // The writer syncs the anchor once its commit has landed, so an
        // anchor read after the snapshot is pinned can carry a head this
        // snapshot never sees, which the proof cannot tell from a database
        // that fell behind its anchor.
        let anchored = self
            .serving_owner
            .companion_anchor()
            .map_err(|error| FindingMarketStoreError::Unavailable(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_companion_custody(&transaction, &anchored)
            .map_err(|error| FindingMarketStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

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
        // Discovery under-advertises on a trailing snapshot; the atomic
        // purchase gate re-checks on the authority connection, so this
        // read never queues behind a write transaction.
        let mut connection = self.read_connection.lock().map_err(|_| {
            FindingMarketStoreError::Unavailable(
                "sqlite finding market read companion lock poisoned".to_owned(),
            )
        })?;
        let transaction = self.begin_companion_read(&mut connection)?;
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
