use super::*;

impl SqliteBudgetStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BudgetStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS capability_grant_budgets (
                capability_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                invocation_count INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                seq INTEGER NOT NULL DEFAULT 0,
                total_cost_exposed INTEGER NOT NULL DEFAULT 0,
                total_cost_realized_spend INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (capability_id, grant_index)
            );

            CREATE INDEX IF NOT EXISTS idx_capability_grant_budgets_updated_at
                ON capability_grant_budgets(updated_at);

            CREATE TABLE IF NOT EXISTS budget_replication_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                next_seq INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS budget_authorization_holds (
                hold_id TEXT PRIMARY KEY,
                capability_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                authorized_exposure_units INTEGER NOT NULL,
                remaining_exposure_units INTEGER NOT NULL,
                invocation_count_debited INTEGER NOT NULL,
                disposition TEXT NOT NULL,
                authority_id TEXT,
                lease_id TEXT,
                lease_epoch INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_budget_authorization_holds_capability
                ON budget_authorization_holds(capability_id, grant_index);

            CREATE TABLE IF NOT EXISTS budget_mutation_events (
                event_id TEXT PRIMARY KEY,
                hold_id TEXT,
                capability_id TEXT NOT NULL,
                grant_index INTEGER NOT NULL,
                kind TEXT NOT NULL,
                allowed INTEGER,
                recorded_at INTEGER NOT NULL,
                event_seq INTEGER,
                usage_seq INTEGER,
                exposure_units INTEGER NOT NULL DEFAULT 0,
                realized_spend_units INTEGER NOT NULL DEFAULT 0,
                max_invocations INTEGER,
                max_exposure_per_invocation INTEGER,
                max_total_exposure_units INTEGER,
                invocation_count_after INTEGER NOT NULL,
                total_cost_exposed_after INTEGER NOT NULL,
                total_cost_realized_spend_after INTEGER NOT NULL,
                authority_id TEXT,
                lease_id TEXT,
                lease_epoch INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_budget_mutation_events_capability
                ON budget_mutation_events(capability_id, grant_index, recorded_at);

            CREATE UNIQUE INDEX IF NOT EXISTS idx_budget_mutation_events_event_seq
                ON budget_mutation_events(event_seq);
            "#,
        )?;
        connection.execute(
            r#"
            INSERT INTO budget_replication_meta (singleton, next_seq)
            VALUES (1, 0)
            ON CONFLICT(singleton) DO NOTHING
            "#,
            [],
        )?;
        ensure_budget_seq_column(&connection)?;
        ensure_split_budget_cost_columns(&connection)?;
        ensure_budget_hold_authority_columns(&connection)?;
        ensure_budget_mutation_event_authority_columns(&connection)?;
        ensure_budget_mutation_event_seq_column(&connection)?;
        initialize_budget_replication_seq(&mut connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(super) fn connection(&self) -> Result<MutexGuard<'_, Connection>, BudgetStoreError> {
        self.connection.lock().map_err(|_| {
            BudgetStoreError::Invariant("sqlite budget store lock poisoned".to_string())
        })
    }

    pub fn upsert_usage(&self, record: &BudgetUsageRecord) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::upsert_usage_in_transaction(&transaction, record)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn import_snapshot_records(
        &self,
        usages: &[BudgetUsageRecord],
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for usage in usages {
            Self::upsert_usage_in_transaction(&transaction, usage)?;
        }
        for event in events {
            Self::import_mutation_record_in_transaction(&transaction, event)?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn upsert_usage_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetUsageRecord,
    ) -> Result<(), BudgetStoreError> {
        raise_budget_replication_seq_floor(transaction, record.seq)?;
        transaction.execute(
            r#"
            INSERT INTO capability_grant_budgets (
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                invocation_count = CASE
                    WHEN excluded.seq >= capability_grant_budgets.seq
                        THEN excluded.invocation_count
                    ELSE capability_grant_budgets.invocation_count
                END,
                updated_at = CASE
                    WHEN excluded.seq >= capability_grant_budgets.seq
                        THEN excluded.updated_at
                    ELSE capability_grant_budgets.updated_at
                END,
                total_cost_exposed = CASE
                    WHEN excluded.seq >= capability_grant_budgets.seq
                        THEN excluded.total_cost_exposed
                    ELSE capability_grant_budgets.total_cost_exposed
                END,
                total_cost_realized_spend = CASE
                    WHEN excluded.seq >= capability_grant_budgets.seq
                        THEN excluded.total_cost_realized_spend
                    ELSE capability_grant_budgets.total_cost_realized_spend
                END,
                seq = MAX(capability_grant_budgets.seq, excluded.seq)
            "#,
            params![
                &record.capability_id,
                record.grant_index as i64,
                record.invocation_count as i64,
                record.updated_at,
                budget_sqlite_i64(record.seq, "budget usage sequence")?,
                budget_sqlite_i64(record.total_cost_exposed, "total_cost_exposed")?,
                budget_sqlite_i64(
                    record.total_cost_realized_spend,
                    "total_cost_realized_spend",
                )?,
            ],
        )?;
        Ok(())
    }

    pub fn delete_mutation_event(&self, event_id: &str) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM budget_mutation_events WHERE event_id = ?1",
            params![event_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_hold(&self, hold_id: &str) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
            params![hold_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn hold_authority(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let authority = Self::load_hold(&transaction, hold_id)?.and_then(|hold| hold.authority);
        transaction.rollback()?;
        Ok(authority)
    }

    pub fn import_mutation_record(
        &self,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::import_mutation_record_in_transaction(&transaction, record)?;
        transaction.commit()?;
        Ok(())
    }

    fn import_mutation_record_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        raise_budget_replication_seq_floor(transaction, record.event_seq)?;
        if let Some(usage_seq) = record.usage_seq {
            raise_budget_replication_seq_floor(transaction, usage_seq)?;
        }

        let duplicate_event = if let Some(existing) =
            Self::load_mutation_event(transaction, &record.event_id)?
        {
            if !Self::same_imported_mutation(&existing, record) {
                if Self::rolled_back_authorize_can_be_replaced(transaction, &existing, record)? {
                    transaction.execute(
                        "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                        params![record.event_id],
                    )?;
                    if let Some(hold_id) = record.hold_id.as_deref() {
                        transaction.execute(
                            "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
                            params![hold_id],
                        )?;
                    }
                    false
                } else {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget event_id `{}` was reused for a different mutation",
                        record.event_id
                    )));
                }
            } else {
                true
            }
        } else {
            transaction.execute(
                r#"
                INSERT INTO budget_mutation_events (
                    event_id,
                    hold_id,
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
                    recorded_at,
                    event_seq,
                    usage_seq,
                    exposure_units,
                    realized_spend_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    invocation_count_after,
                    total_cost_exposed_after,
                    total_cost_realized_spend_after,
                    authority_id,
                    lease_id,
                    lease_epoch
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                "#,
                params![
                    record.event_id,
                    record.hold_id,
                    record.capability_id,
                    i64::from(record.grant_index),
                    record.kind.as_str(),
                    record.allowed.map(|value| if value { 1_i64 } else { 0_i64 }),
                    record.recorded_at,
                    budget_sqlite_i64(record.event_seq, "budget event sequence")?,
                    optional_budget_sqlite_i64(record.usage_seq, "budget usage sequence")?,
                    budget_sqlite_i64(record.exposure_units, "exposure_units")?,
                    budget_sqlite_i64(record.realized_spend_units, "realized_spend_units")?,
                    record.max_invocations.map(i64::from),
                    optional_budget_sqlite_i64(
                        record.max_cost_per_invocation,
                        "max_exposure_per_invocation",
                    )?,
                    optional_budget_sqlite_i64(
                        record.max_total_cost_units,
                        "max_total_exposure_units",
                    )?,
                    i64::from(record.invocation_count_after),
                    budget_sqlite_i64(
                        record.total_cost_exposed_after,
                        "total_cost_exposed_after",
                    )?,
                    budget_sqlite_i64(
                        record.total_cost_realized_spend_after,
                        "total_cost_realized_spend_after",
                    )?,
                    record.authority.as_ref().map(|value| value.authority_id.as_str()),
                    record.authority.as_ref().map(|value| value.lease_id.as_str()),
                    optional_budget_sqlite_i64(
                        record.authority.as_ref().map(|value| value.lease_epoch),
                        "lease_epoch",
                    )?,
                ],
            )?;
            false
        };

        if duplicate_event {
            return Ok(());
        }

        Self::apply_imported_hold_state(transaction, record)?;
        Ok(())
    }

    fn same_imported_mutation(
        existing: &BudgetMutationRecord,
        imported: &BudgetMutationRecord,
    ) -> bool {
        existing.event_id == imported.event_id
            && existing.hold_id == imported.hold_id
            && existing.capability_id == imported.capability_id
            && existing.grant_index == imported.grant_index
            && existing.kind == imported.kind
            && existing.allowed == imported.allowed
            && existing.exposure_units == imported.exposure_units
            && existing.realized_spend_units == imported.realized_spend_units
            && existing.max_invocations == imported.max_invocations
            && existing.max_cost_per_invocation == imported.max_cost_per_invocation
            && existing.max_total_cost_units == imported.max_total_cost_units
            && existing.invocation_count_after == imported.invocation_count_after
            && existing.total_cost_exposed_after == imported.total_cost_exposed_after
            && existing.total_cost_realized_spend_after == imported.total_cost_realized_spend_after
            && existing.authority == imported.authority
    }

    pub fn list_usages_after(
        &self,
        limit: usize,
        after_seq: Option<u64>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            FROM capability_grant_budgets
            WHERE (?1 IS NULL OR seq > ?1)
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(
            params![
                optional_budget_sqlite_i64(after_seq, "budget usage sequence")?,
                limit as i64
            ],
            record_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_all_usages(&self) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            FROM capability_grant_budgets
            ORDER BY updated_at DESC, capability_id ASC, grant_index ASC
            "#,
        )?;
        let rows = statement.query_map([], record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_mutation_events_after_seq(
        &self,
        limit: usize,
        after_event_seq: u64,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT
                event_id,
                hold_id,
                capability_id,
                grant_index,
                kind,
                allowed,
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units,
                realized_spend_units,
                max_invocations,
                max_exposure_per_invocation,
                max_total_exposure_units,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority_id,
                lease_id,
                lease_epoch
            FROM budget_mutation_events
            WHERE event_seq > ?1
            ORDER BY event_seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(
            params![
                budget_sqlite_i64(after_event_seq, "budget event sequence")?,
                limit as i64
            ],
            mutation_record_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn generated_event_id(
        transaction: &rusqlite::Transaction<'_>,
    ) -> Result<String, BudgetStoreError> {
        let count =
            transaction.query_row("SELECT COUNT(*) FROM budget_mutation_events", [], |row| {
                row.get::<_, i64>(0)
            })?;
        Ok(format!(
            "sqlite-budget-event-{}-{}",
            unix_now(),
            count.max(0) + 1
        ))
    }

    pub(super) fn load_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<Option<SqliteBudgetHold>, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT
                    hold_id,
                    capability_id,
                    grant_index,
                    authorized_exposure_units,
                    remaining_exposure_units,
                    invocation_count_debited,
                    disposition,
                    authority_id,
                    lease_id,
                    lease_epoch
                FROM budget_authorization_holds
                WHERE hold_id = ?1
                "#,
                params![hold_id],
                |row| {
                    let disposition = row.get::<_, String>(6)?;
                    let authority =
                        sqlite_budget_event_authority(row.get(7)?, row.get(8)?, row.get(9)?)?;
                    Ok(SqliteBudgetHold {
                        hold_id: row.get(0)?,
                        capability_id: row.get(1)?,
                        grant_index: budget_usize_from_row(row, 2, "grant_index")?,
                        authorized_exposure_units: budget_u64_from_row(
                            row,
                            3,
                            "authorized_exposure_units",
                        )?,
                        remaining_exposure_units: budget_u64_from_row(
                            row,
                            4,
                            "remaining_exposure_units",
                        )?,
                        invocation_count_debited: row.get::<_, i64>(5)? > 0,
                        disposition: HoldDisposition::parse(&disposition).ok_or_else(|| {
                            rusqlite::Error::FromSqlConversionFailure(
                                6,
                                rusqlite::types::Type::Text,
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("unknown hold disposition `{disposition}`"),
                                )),
                            )
                        })?,
                        authority,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn load_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT
                    event_id,
                    hold_id,
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
                    recorded_at,
                    event_seq,
                    usage_seq,
                    exposure_units,
                    realized_spend_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    invocation_count_after,
                    total_cost_exposed_after,
                    total_cost_realized_spend_after,
                    authority_id,
                    lease_id,
                    lease_epoch
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                mutation_record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(super) fn create_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let now = unix_now();
        transaction.execute(
            r#"
            INSERT INTO budget_authorization_holds (
                hold_id,
                capability_id,
                grant_index,
                authorized_exposure_units,
                remaining_exposure_units,
                invocation_count_debited,
                disposition,
                authority_id,
                lease_id,
                lease_epoch,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, ?10, ?10)
            "#,
            params![
                hold_id,
                capability_id,
                grant_index as i64,
                budget_sqlite_i64(authorized_exposure_units, "authorized_exposure_units")?,
                budget_sqlite_i64(authorized_exposure_units, "remaining_exposure_units")?,
                HoldDisposition::Open.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                optional_budget_sqlite_i64(
                    authority.map(|value| value.lease_epoch),
                    "lease_epoch",
                )?,
                now,
            ],
        )?;
        Ok(())
    }

    pub(super) fn update_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        remaining_exposure_units: u64,
        disposition: HoldDisposition,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = ?2,
                disposition = ?3,
                authority_id = ?4,
                lease_id = ?5,
                lease_epoch = ?6,
                updated_at = ?7
            WHERE hold_id = ?1
            "#,
            params![
                hold_id,
                budget_sqlite_i64(remaining_exposure_units, "remaining_exposure_units")?,
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                optional_budget_sqlite_i64(
                    authority.map(|value| value.lease_epoch),
                    "lease_epoch",
                )?,
                unix_now(),
            ],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn upsert_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        remaining_exposure_units: u64,
        disposition: HoldDisposition,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let now = unix_now();
        transaction.execute(
            r#"
            INSERT INTO budget_authorization_holds (
                hold_id,
                capability_id,
                grant_index,
                authorized_exposure_units,
                remaining_exposure_units,
                invocation_count_debited,
                disposition,
                authority_id,
                lease_id,
                lease_epoch,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, ?10, ?10)
            ON CONFLICT(hold_id) DO UPDATE SET
                capability_id = excluded.capability_id,
                grant_index = excluded.grant_index,
                authorized_exposure_units = excluded.authorized_exposure_units,
                remaining_exposure_units = excluded.remaining_exposure_units,
                invocation_count_debited = excluded.invocation_count_debited,
                disposition = excluded.disposition,
                authority_id = excluded.authority_id,
                lease_id = excluded.lease_id,
                lease_epoch = excluded.lease_epoch,
                updated_at = excluded.updated_at
            "#,
            params![
                hold_id,
                capability_id,
                grant_index as i64,
                budget_sqlite_i64(authorized_exposure_units, "authorized_exposure_units")?,
                budget_sqlite_i64(remaining_exposure_units, "remaining_exposure_units")?,
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                optional_budget_sqlite_i64(
                    authority.map(|value| value.lease_epoch),
                    "lease_epoch",
                )?,
                now,
            ],
        )?;
        Ok(())
    }

    pub(super) fn delete_hold_if_exists(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<(), BudgetStoreError> {
        transaction.execute(
            "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
            params![hold_id],
        )?;
        Ok(())
    }

    fn apply_imported_hold_state(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let Some(hold_id) = record.hold_id.as_deref() else {
            return Ok(());
        };

        match record.kind {
            BudgetMutationKind::IncrementInvocation => Ok(()),
            BudgetMutationKind::AuthorizeExposure => {
                if record.allowed == Some(true) {
                    Self::upsert_hold(
                        transaction,
                        hold_id,
                        &record.capability_id,
                        record.grant_index as usize,
                        record.exposure_units,
                        record.exposure_units,
                        HoldDisposition::Open,
                        record.authority.as_ref(),
                    )
                } else {
                    Self::delete_hold_if_exists(transaction, hold_id)
                }
            }
            BudgetMutationKind::ReleaseExposure => {
                let hold = Self::load_hold(transaction, hold_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing budget hold `{hold_id}` while importing release event"
                    ))
                })?;
                if hold.capability_id != record.capability_id
                    || hold.grant_index != record.grant_index as usize
                {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` does not match capability/grant"
                    )));
                }
                let remaining = hold
                    .remaining_exposure_units
                    .checked_sub(record.exposure_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "budget hold `{hold_id}` cannot release more than remaining exposure"
                        ))
                    })?;
                let disposition = if remaining == 0 {
                    HoldDisposition::Released
                } else {
                    HoldDisposition::Open
                };
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    hold.authorized_exposure_units,
                    remaining,
                    disposition,
                    record.authority.as_ref().or(hold.authority.as_ref()),
                )
            }
            BudgetMutationKind::ReverseExposure => {
                let authorized_exposure_units = Self::load_hold(transaction, hold_id)?
                    .map(|hold| hold.authorized_exposure_units)
                    .unwrap_or(record.exposure_units);
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    authorized_exposure_units,
                    0,
                    HoldDisposition::Reversed,
                    record.authority.as_ref(),
                )
            }
            BudgetMutationKind::ReconcileSpend => {
                let authorized_exposure_units = Self::load_hold(transaction, hold_id)?
                    .map(|hold| hold.authorized_exposure_units)
                    .unwrap_or(record.exposure_units);
                Self::upsert_hold(
                    transaction,
                    hold_id,
                    &record.capability_id,
                    record.grant_index as usize,
                    authorized_exposure_units,
                    0,
                    HoldDisposition::Reconciled,
                    record.authority.as_ref(),
                )
            }
        }
    }

    pub(super) fn ensure_open_hold(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<SqliteBudgetHold, BudgetStoreError> {
        let hold = Self::load_hold(transaction, hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing budget hold `{hold_id}`"))
        })?;
        if hold.capability_id != capability_id || hold.grant_index != grant_index {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match capability/grant"
            )));
        }
        if hold.disposition != HoldDisposition::Open {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is no longer open"
            )));
        }
        Ok(hold)
    }

    pub(super) fn validate_hold_authority(
        hold_id: &str,
        current: Option<&BudgetEventAuthority>,
        requested: Option<&BudgetEventAuthority>,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        match (current, requested) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` was created without authority lease metadata"
            ))),
            (Some(_), None) => Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` requires authority lease metadata"
            ))),
            (Some(current), Some(requested)) => {
                if current.authority_id != requested.authority_id {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority_id does not match the open lease"
                    )));
                }
                if requested.lease_id != current.lease_id {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` lease_id does not match the open lease epoch"
                    )));
                }
                if requested.lease_epoch < current.lease_epoch {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority lease epoch regressed"
                    )));
                }
                if requested.lease_epoch > current.lease_epoch {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` authority lease epoch advanced beyond the open lease"
                    )));
                }
                Ok(Some(requested.clone()))
            }
        }
    }

    fn existing_increment_allowed(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<Option<bool>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
        let existing = transaction
            .query_row(
                r#"
                SELECT capability_id, grant_index, kind, allowed, max_invocations
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        budget_usize_from_row(row, 1, "grant_index")?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        optional_budget_u32_from_row(row, 4, "max_invocations")?,
                    ))
                },
            )
            .optional()?;
        let Some((
            existing_capability_id,
            existing_grant_index,
            existing_kind,
            existing_allowed,
            existing_max_invocations,
        )) = existing
        else {
            return Ok(None);
        };
        let mutation_matches = existing_capability_id == capability_id
            && existing_grant_index == grant_index
            && existing_kind == BudgetMutationKind::IncrementInvocation.as_str()
            && existing_max_invocations == max_invocations;
        if !mutation_matches {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        Ok(Some(existing_allowed.unwrap_or(0) > 0))
    }

    fn sqlite_like_prefix_pattern(prefix: &str) -> String {
        let mut pattern = String::with_capacity(prefix.len() + 1);
        for ch in prefix.chars() {
            match ch {
                '\\' | '%' | '_' => {
                    pattern.push('\\');
                    pattern.push(ch);
                }
                _ => pattern.push(ch),
            }
        }
        pattern.push('%');
        pattern
    }

    pub(super) fn rollback_event_exists(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
    ) -> Result<bool, BudgetStoreError> {
        let rollback_prefix = format!("{event_id}:rollback:");
        let rollback_prefix_pattern = Self::sqlite_like_prefix_pattern(&rollback_prefix);
        Ok(transaction
            .query_row(
                r#"
                SELECT 1
                FROM budget_mutation_events
                WHERE event_id LIKE ?1 ESCAPE '\'
                LIMIT 1
                "#,
                params![rollback_prefix_pattern],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    fn rolled_back_authorize_can_be_replaced(
        transaction: &rusqlite::Transaction<'_>,
        existing: &BudgetMutationRecord,
        replacement: &BudgetMutationRecord,
    ) -> Result<bool, BudgetStoreError> {
        if existing.kind != BudgetMutationKind::AuthorizeExposure
            || replacement.kind != BudgetMutationKind::AuthorizeExposure
            || existing.allowed != Some(true)
            || replacement.allowed != Some(true)
        {
            return Ok(false);
        }
        let same_mutation_scope = existing.hold_id == replacement.hold_id
            && existing.capability_id == replacement.capability_id
            && existing.grant_index == replacement.grant_index
            && existing.exposure_units == replacement.exposure_units
            && existing.realized_spend_units == replacement.realized_spend_units
            && existing.max_invocations == replacement.max_invocations
            && existing.max_cost_per_invocation == replacement.max_cost_per_invocation
            && existing.max_total_cost_units == replacement.max_total_cost_units;
        if !same_mutation_scope {
            return Ok(false);
        }
        Self::rollback_event_exists(transaction, &existing.event_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn existing_event_allowed(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        kind: BudgetMutationKind,
        capability_id: &str,
        grant_index: usize,
        hold_id: Option<&str>,
        _authority: Option<&BudgetEventAuthority>,
        exposure_units: u64,
        realized_spend_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<Option<Option<bool>>, BudgetStoreError> {
        let Some(event_id) = event_id else {
            return Ok(None);
        };
        let existing = transaction
            .query_row(
                r#"
                SELECT
                    hold_id,
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
                    exposure_units,
                    realized_spend_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    invocation_count_after,
                    total_cost_exposed_after,
                    total_cost_realized_spend_after
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        budget_usize_from_row(row, 2, "grant_index")?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        budget_u64_from_row(row, 5, "exposure_units")?,
                        budget_u64_from_row(row, 6, "realized_spend_units")?,
                        optional_budget_u32_from_row(row, 7, "max_invocations")?,
                        optional_budget_u64_from_row(row, 8, "max_exposure_per_invocation")?,
                        optional_budget_u64_from_row(row, 9, "max_total_exposure_units")?,
                        budget_u32_from_row(row, 10, "invocation_count_after")?,
                        budget_u64_from_row(row, 11, "total_cost_exposed_after")?,
                        budget_u64_from_row(row, 12, "total_cost_realized_spend_after")?,
                    ))
                },
            )
            .optional()?;
        let Some((
            existing_hold_id,
            existing_capability_id,
            existing_grant_index,
            existing_kind,
            existing_allowed,
            existing_exposure_units,
            existing_realized_spend_units,
            existing_max_invocations,
            existing_max_exposure_per_invocation,
            existing_max_total_exposure_units,
            existing_invocation_count_after,
            existing_total_cost_exposed_after,
            existing_total_cost_realized_spend_after,
        )) = existing
        else {
            return Ok(None);
        };
        let max_invocations_matches = existing_max_invocations == max_invocations;
        let max_per_matches = existing_max_exposure_per_invocation == max_cost_per_invocation;
        let max_total_matches = existing_max_total_exposure_units == max_total_cost_units;
        let mutation_matches = existing_capability_id == capability_id
            && existing_grant_index == grant_index
            && existing_kind == kind.as_str()
            && existing_hold_id.as_deref() == hold_id
            && existing_exposure_units == exposure_units
            && existing_realized_spend_units == realized_spend_units
            && max_invocations_matches
            && max_per_matches
            && max_total_matches;
        let existing_allowed = existing_allowed.map(|value| value > 0);
        let rollback_exists = kind == BudgetMutationKind::AuthorizeExposure
            && existing_allowed == Some(true)
            && Self::rollback_event_exists(transaction, event_id)?;
        if !mutation_matches {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        if rollback_exists {
            let current = transaction
                .query_row(
                    r#"
                    SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                    FROM capability_grant_budgets
                    WHERE capability_id = ?1 AND grant_index = ?2
                    "#,
                    params![capability_id, grant_index as i64],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "invocation_count")?,
                            budget_u64_from_row(row, 1, "total_cost_exposed")?,
                            budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                        ))
                    },
                )
                .optional()?;
            let usage_matches = current.is_some_and(
                |(invocation_count, total_cost_exposed, total_cost_realized_spend)| {
                    invocation_count == existing_invocation_count_after
                        && total_cost_exposed == existing_total_cost_exposed_after
                        && total_cost_realized_spend == existing_total_cost_realized_spend_after
                },
            );
            let hold_matches = match hold_id {
                Some(hold_id) => Self::load_hold(transaction, hold_id)?.is_some_and(|hold| {
                    hold.capability_id == capability_id
                        && hold.grant_index == grant_index
                        && hold.authorized_exposure_units == exposure_units
                        && hold.remaining_exposure_units == exposure_units
                        && hold.invocation_count_debited
                        && hold.disposition == HoldDisposition::Open
                }),
                None => true,
            };
            if usage_matches && hold_matches {
                return Ok(Some(existing_allowed));
            }
            transaction.execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )?;
            if let Some(hold_id) = hold_id {
                transaction.execute(
                    "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
                    params![hold_id],
                )?;
            }
            return Ok(None);
        }
        Ok(Some(existing_allowed))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn append_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        hold_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        capability_id: &str,
        grant_index: usize,
        kind: BudgetMutationKind,
        allowed: Option<bool>,
        event_seq: u64,
        usage_seq: Option<u64>,
        exposure_units: u64,
        realized_spend_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        invocation_count_after: u32,
        total_cost_exposed_after: u64,
        total_cost_realized_spend_after: u64,
    ) -> Result<(), BudgetStoreError> {
        let event_id = match event_id {
            Some(event_id) => event_id.to_string(),
            None => Self::generated_event_id(transaction)?,
        };
        transaction.execute(
            r#"
            INSERT INTO budget_mutation_events (
                event_id,
                hold_id,
                capability_id,
                grant_index,
                kind,
                allowed,
                recorded_at,
                event_seq,
                usage_seq,
                exposure_units,
                realized_spend_units,
                max_invocations,
                max_exposure_per_invocation,
                max_total_exposure_units,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend_after,
                authority_id,
                lease_id,
                lease_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
            "#,
            params![
                event_id,
                hold_id,
                capability_id,
                grant_index as i64,
                kind.as_str(),
                allowed.map(|value| if value { 1_i64 } else { 0_i64 }),
                unix_now(),
                budget_sqlite_i64(event_seq, "budget event sequence")?,
                optional_budget_sqlite_i64(usage_seq, "budget usage sequence")?,
                budget_sqlite_i64(exposure_units, "exposure_units")?,
                budget_sqlite_i64(realized_spend_units, "realized_spend_units")?,
                max_invocations.map(i64::from),
                optional_budget_sqlite_i64(
                    max_cost_per_invocation,
                    "max_exposure_per_invocation",
                )?,
                optional_budget_sqlite_i64(
                    max_total_cost_units,
                    "max_total_exposure_units",
                )?,
                invocation_count_after as i64,
                budget_sqlite_i64(total_cost_exposed_after, "total_cost_exposed_after")?,
                budget_sqlite_i64(
                    total_cost_realized_spend_after,
                    "total_cost_realized_spend_after",
                )?,
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                optional_budget_sqlite_i64(
                    authority.map(|value| value.lease_epoch),
                    "lease_epoch",
                )?,
            ],
        )?;
        Ok(())
    }

    pub fn try_increment_with_event_id(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(allowed) = SqliteBudgetStore::existing_increment_allowed(
            &transaction,
            event_id,
            capability_id,
            grant_index,
            max_invocations,
        )? {
            transaction.rollback()?;
            return Ok(allowed);
        }

        let current: Option<(u32, u64, u64)> = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;
        let (current, total_cost_exposed, total_cost_realized_spend) = current.unwrap_or((0, 0, 0));
        let updated_at = unix_now();

        let allowed = budget_increment_admits(current, max_invocations);
        if !allowed {
            let event_seq = allocate_budget_replication_seq(&transaction)?;
            SqliteBudgetStore::append_mutation_event(
                &transaction,
                event_id,
                None,
                None,
                capability_id,
                grant_index,
                BudgetMutationKind::IncrementInvocation,
                Some(false),
                event_seq,
                None,
                0,
                0,
                max_invocations,
                None,
                None,
                current,
                total_cost_exposed,
                total_cost_realized_spend,
            )?;
            transaction.commit()?;
            return Ok(false);
        }

        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            INSERT INTO capability_grant_budgets (
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            ) VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)
            ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                invocation_count = excluded.invocation_count,
                updated_at = excluded.updated_at,
                seq = excluded.seq
            "#,
            params![
                capability_id,
                grant_index as i64,
                current.saturating_add(1) as i64,
                updated_at,
                budget_sqlite_i64(seq, "budget usage sequence")?,
            ],
        )?;
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            None,
            None,
            capability_id,
            grant_index,
            BudgetMutationKind::IncrementInvocation,
            Some(true),
            seq,
            Some(seq),
            0,
            0,
            max_invocations,
            None,
            None,
            current.saturating_add(1),
            total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(true)
    }
}
