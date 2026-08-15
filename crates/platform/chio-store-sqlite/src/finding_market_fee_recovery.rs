use super::*;

impl SqliteFindingMarketStore {
    /// Recover the one open participation intent identified by the request's
    /// Finding and signed fee schedule, independent of the current admission.
    pub fn get_pending_participation_fee_intent(
        &self,
        finding_id: &str,
        fee_schedule_envelope_sha256: &str,
    ) -> Result<Option<FindingFeeEventRecord>, FindingMarketStoreError> {
        require_hex64(finding_id, "finding_id")?;
        require_hex64(fee_schedule_envelope_sha256, "fee_schedule_envelope_sha256")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT idempotency_key FROM fee_events
                WHERE finding_id = ?1 AND fee_schedule_envelope_sha256 = ?2
                  AND event_kind = 'participation_epoch'
                  AND state IN ('intent', 'failed')
                ORDER BY epoch_index ASC, idempotency_key ASC
                LIMIT 2
                "#,
            )
            .map_err(sqlite_error)?;
        let keys = statement
            .query_map(params![finding_id, fee_schedule_envelope_sha256], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        match keys.as_slice() {
            [] => Ok(None),
            [key] => load_fee_event_tx(&transaction, key),
            _ => Err(FindingMarketStoreError::Conflict(
                "more than one participation fee intent is pending for the signed schedule"
                    .to_owned(),
            )),
        }
    }
}
