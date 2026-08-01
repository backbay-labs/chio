use super::*;

impl SqliteBudgetStore {
    pub(super) fn require_standalone_mutation(
        &self,
        operation: &str,
    ) -> Result<(), BudgetStoreError> {
        if self.serving_owner.is_none() {
            return Ok(());
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        crate::serving_owner::verify_budget_fence(&transaction, self.serving_owner.as_deref())?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .verify_authority_anchor(&transaction)
                .map_err(crate::budget_store::store::map_serving_owner_error)?;
        }
        transaction.rollback()?;
        Err(BudgetStoreError::Invariant(format!(
            "joint sqlite authority rejects legacy {operation} mutation"
        )))
    }

    pub(super) fn reject_structured_hold_from_legacy_writer(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: Option<&str>,
        operation: &str,
    ) -> Result<(), BudgetStoreError> {
        let Some(hold_id) = hold_id else {
            return Ok(());
        };
        type Row = (
            String,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<i64>,
            Option<bool>,
            Option<bool>,
            Option<i64>,
            Option<i64>,
            bool,
            bool,
            bool,
            bool,
            bool,
        );
        let row: Option<Row> = transaction
            .query_row(
                r#"
                SELECT projection_kind, operation_id, revocation_set_digest,
                       expected_quota_count, expected_artifact_count,
                       has_cumulative_approval, has_revocation_commit,
                       expected_revocation_count, trusted_capture_time,
                       EXISTS(SELECT 1 FROM budget_hold_revocation_members
                              WHERE hold_id = parent.hold_id),
                       EXISTS(SELECT 1 FROM budget_hold_quota_members
                              WHERE hold_id = parent.hold_id),
                       EXISTS(SELECT 1 FROM budget_hold_authorization_artifacts
                              WHERE hold_id = parent.hold_id),
                       EXISTS(SELECT 1 FROM budget_cumulative_approval_operations
                              WHERE hold_id = parent.hold_id),
                       EXISTS(SELECT 1 FROM budget_hold_revocation_commits
                              WHERE hold_id = parent.hold_id)
                FROM budget_authorization_holds AS parent WHERE hold_id = ?1
                "#,
                rusqlite::params![hold_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(()),
            Some(row) if row.0 == "composite_v1" => Err(BudgetStoreError::Invariant(format!(
                "legacy {operation} cannot mutate structured budget hold `{hold_id}`"
            ))),
            Some(row)
                if row.0 == "legacy"
                    && row.1.is_none()
                    && row.2.is_none()
                    && row.3.is_none()
                    && row.4.is_none()
                    && row.5.is_none()
                    && row.6.is_none()
                    && row.7.is_none()
                    && row.8.is_none()
                    && !row.9
                    && !row.10
                    && !row.11
                    && !row.12
                    && !row.13 =>
            {
                Ok(())
            }
            Some(_) => Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` has an inconsistent projection discriminator"
            ))),
        }
    }

    pub(super) fn reject_legacy_admission_after_composite_history(
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<(), BudgetStoreError> {
        let exists = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_mutation_events
                WHERE capability_id = ?1 AND grant_index = ?2
                  AND projection_kind = 'composite_v1'
            )
            "#,
            rusqlite::params![capability_id, grant_index as i64],
            |row| row.get::<_, bool>(0),
        )?;
        if exists {
            return Err(BudgetStoreError::Invariant(format!(
                "legacy budget admission is disabled after structured history for `{capability_id}` grant {grant_index}"
            )));
        }
        Ok(())
    }
}
