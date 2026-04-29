use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::budget_store::{BudgetEventAuthority, BudgetMutationKind, BudgetMutationRecord};
use chio_kernel::{BudgetStore, BudgetStoreError, BudgetUsageRecord};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub struct SqliteBudgetStore {
    connection: Mutex<Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HoldDisposition {
    Open,
    Released,
    Reversed,
    Reconciled,
}

impl HoldDisposition {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Released => "released",
            Self::Reversed => "reversed",
            Self::Reconciled => "reconciled",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "released" => Some(Self::Released),
            "reversed" => Some(Self::Reversed),
            "reconciled" => Some(Self::Reconciled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqliteBudgetHold {
    hold_id: String,
    capability_id: String,
    grant_index: usize,
    authorized_exposure_units: u64,
    remaining_exposure_units: u64,
    invocation_count_debited: bool,
    disposition: HoldDisposition,
    authority: Option<BudgetEventAuthority>,
}

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

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, BudgetStoreError> {
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
                record.seq as i64,
                record.total_cost_exposed as i64,
                record.total_cost_realized_spend as i64,
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
            if existing != *record {
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
                    record.event_seq as i64,
                    record.usage_seq.map(|value| value as i64),
                    record.exposure_units as i64,
                    record.realized_spend_units as i64,
                    record.max_invocations.map(i64::from),
                    record.max_cost_per_invocation.map(|value| value as i64),
                    record.max_total_cost_units.map(|value| value as i64),
                    i64::from(record.invocation_count_after),
                    record.total_cost_exposed_after as i64,
                    record.total_cost_realized_spend_after as i64,
                    record.authority.as_ref().map(|value| value.authority_id.as_str()),
                    record.authority.as_ref().map(|value| value.lease_id.as_str()),
                    record.authority.as_ref().map(|value| value.lease_epoch as i64),
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
            params![after_seq.map(|value| value as i64), limit as i64],
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
        let rows = statement.query_map(params![after_event_seq as i64, limit as i64], |row| {
            mutation_record_from_row(row)
        })?;
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

    fn load_hold(
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
                        grant_index: row.get::<_, i64>(2)?.max(0) as usize,
                        authorized_exposure_units: row.get::<_, i64>(3)?.max(0) as u64,
                        remaining_exposure_units: row.get::<_, i64>(4)?.max(0) as u64,
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

    fn create_hold(
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
                authorized_exposure_units as i64,
                authorized_exposure_units as i64,
                HoldDisposition::Open.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority.map(|value| value.lease_epoch as i64),
                now,
            ],
        )?;
        Ok(())
    }

    fn update_hold(
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
                remaining_exposure_units as i64,
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority.map(|value| value.lease_epoch as i64),
                unix_now(),
            ],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_hold(
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
                authorized_exposure_units as i64,
                remaining_exposure_units as i64,
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority.map(|value| value.lease_epoch as i64),
                now,
            ],
        )?;
        Ok(())
    }

    fn delete_hold_if_exists(
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

    fn ensure_open_hold(
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

    fn validate_hold_authority(
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
                        row.get::<_, i64>(1)?.max(0) as usize,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
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
            && existing_max_invocations.map(|value| value.max(0) as u32) == max_invocations;
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

    fn rollback_event_exists(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
    ) -> Result<bool, BudgetStoreError> {
        let legacy_rollback_event_id = format!("{event_id}:rollback");
        let rollback_prefix = format!("{event_id}:rollback:");
        let rollback_prefix_pattern = Self::sqlite_like_prefix_pattern(&rollback_prefix);
        Ok(transaction
            .query_row(
                r#"
                SELECT 1
                FROM budget_mutation_events
                WHERE event_id = ?1
                   OR event_id LIKE ?2 ESCAPE '\'
                LIMIT 1
                "#,
                params![legacy_rollback_event_id, rollback_prefix_pattern],
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
    fn existing_event_allowed(
        transaction: &rusqlite::Transaction<'_>,
        event_id: Option<&str>,
        kind: BudgetMutationKind,
        capability_id: &str,
        grant_index: usize,
        hold_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
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
                    total_cost_realized_spend_after,
                    authority_id,
                    lease_id,
                    lease_epoch
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                |row| {
                    let authority =
                        sqlite_budget_event_authority(row.get(13)?, row.get(14)?, row.get(15)?)?;
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?.max(0) as usize,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, i64>(5)?.max(0) as u64,
                        row.get::<_, i64>(6)?.max(0) as u64,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                        row.get::<_, i64>(10)?.max(0) as u32,
                        row.get::<_, i64>(11)?.max(0) as u64,
                        row.get::<_, i64>(12)?.max(0) as u64,
                        authority,
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
            existing_authority,
        )) = existing
        else {
            return Ok(None);
        };
        let max_invocations_matches =
            existing_max_invocations.map(|value| value.max(0) as u32) == max_invocations;
        let max_per_matches = existing_max_exposure_per_invocation.map(|value| value.max(0) as u64)
            == max_cost_per_invocation;
        let max_total_matches = existing_max_total_exposure_units.map(|value| value.max(0) as u64)
            == max_total_cost_units;
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
                            row.get::<_, i64>(0)?.max(0) as u32,
                            row.get::<_, i64>(1)?.max(0) as u64,
                            row.get::<_, i64>(2)?.max(0) as u64,
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
        if existing_authority.as_ref() != authority {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        Ok(Some(existing_allowed))
    }

    #[allow(clippy::too_many_arguments)]
    fn append_mutation_event(
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
                event_seq as i64,
                usage_seq.map(|value| value as i64),
                exposure_units as i64,
                realized_spend_units as i64,
                max_invocations.map(i64::from),
                max_cost_per_invocation.map(|value| value as i64),
                max_total_cost_units.map(|value| value as i64),
                invocation_count_after as i64,
                total_cost_exposed_after as i64,
                total_cost_realized_spend_after as i64,
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority.map(|value| value.lease_epoch as i64),
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
                        row.get::<_, i64>(0)?.max(0) as u32,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, i64>(2)?.max(0) as u64,
                    ))
                },
            )
            .optional()?;
        let (current, total_cost_exposed, total_cost_realized_spend) = current.unwrap_or((0, 0, 0));
        let updated_at = unix_now();

        if let Some(max) = max_invocations {
            if current >= max {
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
                seq as i64,
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

impl BudgetStore for SqliteBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_increment_with_event_id(capability_id, grant_index, max_invocations, None)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing_allowed) = SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::AuthorizeExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
        )? {
            transaction.rollback()?;
            return Ok(existing_allowed.unwrap_or(false));
        }

        let row: Option<(i64, u64, u64)> = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, i64>(2)?.max(0) as u64,
                    ))
                },
            )
            .optional()?;
        let (current_count, current_exposed, current_realized) = row.unwrap_or((0, 0, 0));
        let current_count = current_count.max(0) as u32;

        if let Some(hold_id) = hold_id {
            let retry_follows_rollback = match event_id {
                Some(event_id) => Self::rollback_event_exists(&transaction, event_id)?,
                None => false,
            };
            if let Some(hold) = SqliteBudgetStore::load_hold(&transaction, hold_id)? {
                if hold.capability_id == capability_id
                    && hold.grant_index == grant_index
                    && hold.authorized_exposure_units == cost_units
                    && hold.remaining_exposure_units == cost_units
                    && hold.invocation_count_debited
                    && hold.disposition == HoldDisposition::Open
                    && current_exposed >= cost_units
                {
                    let current = transaction
                        .query_row(
                            r#"
                            SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                            FROM capability_grant_budgets
                            WHERE capability_id = ?1 AND grant_index = ?2
                            "#,
                            params![capability_id, grant_index as i64],
                            |row| {
                                Ok((
                                    row.get::<_, i64>(0)?.max(0) as u64,
                                    row.get::<_, i64>(1)?.max(0) as u32,
                                    row.get::<_, i64>(2)?.max(0) as u64,
                                    row.get::<_, i64>(3)?.max(0) as u64,
                                ))
                            },
                        )
                        .optional()?;
                    if let Some((
                        usage_seq,
                        invocation_count_after,
                        total_cost_exposed_after,
                        total_cost_realized_spend_after,
                    )) = current
                    {
                        let event_seq = allocate_budget_replication_seq(&transaction)?;
                        if retry_follows_rollback {
                            SqliteBudgetStore::upsert_hold(
                                &transaction,
                                hold_id,
                                capability_id,
                                grant_index,
                                cost_units,
                                cost_units,
                                HoldDisposition::Open,
                                authority,
                            )?;
                        }
                        SqliteBudgetStore::append_mutation_event(
                            &transaction,
                            event_id,
                            Some(hold_id),
                            authority,
                            capability_id,
                            grant_index,
                            BudgetMutationKind::AuthorizeExposure,
                            Some(true),
                            event_seq,
                            Some(usage_seq),
                            cost_units,
                            0,
                            max_invocations,
                            max_cost_per_invocation,
                            max_total_cost_units,
                            invocation_count_after,
                            total_cost_exposed_after,
                            total_cost_realized_spend_after,
                        )?;
                        transaction.commit()?;
                        return Ok(true);
                    }
                }
            }
            if retry_follows_rollback {
                Self::delete_hold_if_exists(&transaction, hold_id)?;
            }
        }

        let mut allowed = true;

        if let Some(max) = max_invocations {
            if current_count >= max {
                allowed = false;
            }
        }
        if let Some(max_per) = max_cost_per_invocation {
            if cost_units > max_per {
                allowed = false;
            }
        }
        if let Some(max_total) = max_total_cost_units {
            let current_total = checked_committed_cost_units(current_exposed, current_realized)?;
            let new_total = current_total.checked_add(cost_units).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "authorized exposure + cost_units overflowed u64".to_string(),
                )
            })?;
            if new_total > max_total {
                allowed = false;
            }
        }

        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            event_seq,
            usage_seq,
        );
        if allowed {
            if let Some(hold_id) = hold_id {
                let retry_follows_rollback = match event_id {
                    Some(event_id) => Self::rollback_event_exists(&transaction, event_id)?,
                    None => false,
                };
                if retry_follows_rollback {
                    if let Some(hold) = SqliteBudgetStore::load_hold(&transaction, hold_id)? {
                        if hold.capability_id == capability_id
                            && hold.grant_index == grant_index
                            && hold.authorized_exposure_units == cost_units
                            && hold.remaining_exposure_units == cost_units
                            && hold.invocation_count_debited
                            && hold.disposition == HoldDisposition::Open
                            && current_exposed >= cost_units
                        {
                            let current = transaction
                                .query_row(
                                    r#"
                                    SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                                    FROM capability_grant_budgets
                                    WHERE capability_id = ?1 AND grant_index = ?2
                                    "#,
                                    params![capability_id, grant_index as i64],
                                    |row| {
                                        Ok((
                                            row.get::<_, i64>(0)?.max(0) as u64,
                                            row.get::<_, i64>(1)?.max(0) as u32,
                                            row.get::<_, i64>(2)?.max(0) as u64,
                                            row.get::<_, i64>(3)?.max(0) as u64,
                                        ))
                                    },
                                )
                                .optional()?;
                            if let Some((
                                usage_seq,
                                invocation_count_after,
                                total_cost_exposed_after,
                                total_cost_realized_spend_after,
                            )) = current
                            {
                                let event_seq = allocate_budget_replication_seq(&transaction)?;
                                SqliteBudgetStore::upsert_hold(
                                    &transaction,
                                    hold_id,
                                    capability_id,
                                    grant_index,
                                    cost_units,
                                    cost_units,
                                    HoldDisposition::Open,
                                    authority,
                                )?;
                                SqliteBudgetStore::append_mutation_event(
                                    &transaction,
                                    event_id,
                                    Some(hold_id),
                                    authority,
                                    capability_id,
                                    grant_index,
                                    BudgetMutationKind::AuthorizeExposure,
                                    Some(true),
                                    event_seq,
                                    Some(usage_seq),
                                    cost_units,
                                    0,
                                    max_invocations,
                                    max_cost_per_invocation,
                                    max_total_cost_units,
                                    invocation_count_after,
                                    total_cost_exposed_after,
                                    total_cost_realized_spend_after,
                                )?;
                                transaction.commit()?;
                                return Ok(true);
                            }
                        }
                    }
                    Self::delete_hold_if_exists(&transaction, hold_id)?;
                } else if let Some(hold) = SqliteBudgetStore::load_hold(&transaction, hold_id)? {
                    if hold.capability_id == capability_id
                        && hold.grant_index == grant_index
                        && hold.authorized_exposure_units == cost_units
                        && hold.remaining_exposure_units == cost_units
                        && hold.invocation_count_debited
                        && hold.disposition == HoldDisposition::Open
                    {
                        let current = transaction
                            .query_row(
                                r#"
                                SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                                FROM capability_grant_budgets
                                WHERE capability_id = ?1 AND grant_index = ?2
                                "#,
                                params![capability_id, grant_index as i64],
                                |row| {
                                    Ok((
                                        row.get::<_, i64>(0)?.max(0) as u64,
                                        row.get::<_, i64>(1)?.max(0) as u32,
                                        row.get::<_, i64>(2)?.max(0) as u64,
                                        row.get::<_, i64>(3)?.max(0) as u64,
                                    ))
                                },
                            )
                            .optional()?;
                        if let Some((
                            seq,
                            invocation_count_after,
                            total_cost_exposed_after,
                            total_cost_realized_spend_after,
                        )) = current
                        {
                            if total_cost_exposed_after < cost_units {
                                transaction.rollback()?;
                                return Err(BudgetStoreError::Invariant(format!(
                                    "budget hold `{hold_id}` is not reflected in usage totals"
                                )));
                            }
                            SqliteBudgetStore::append_mutation_event(
                                &transaction,
                                event_id,
                                Some(hold_id),
                                authority,
                                capability_id,
                                grant_index,
                                BudgetMutationKind::AuthorizeExposure,
                                Some(true),
                                seq,
                                Some(seq),
                                cost_units,
                                0,
                                max_invocations,
                                max_cost_per_invocation,
                                max_total_cost_units,
                                invocation_count_after,
                                total_cost_exposed_after,
                                total_cost_realized_spend_after,
                            )?;
                            transaction.commit()?;
                            return Ok(true);
                        }
                    }
                    transaction.rollback()?;
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` already exists"
                    )));
                }
            }
            let new_total_cost_exposed =
                current_exposed.checked_add(cost_units).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_exposed + cost_units overflowed u64".to_string(),
                    )
                })?;
            let updated_at = unix_now();
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
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                    invocation_count = excluded.invocation_count,
                    updated_at = excluded.updated_at,
                    seq = excluded.seq,
                    total_cost_exposed = excluded.total_cost_exposed,
                    total_cost_realized_spend = excluded.total_cost_realized_spend
                "#,
                params![
                    capability_id,
                    grant_index as i64,
                    (current_count.saturating_add(1)) as i64,
                    updated_at,
                    seq as i64,
                    new_total_cost_exposed as i64,
                    current_realized as i64,
                ],
            )?;
            if let Some(hold_id) = hold_id {
                SqliteBudgetStore::create_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                    cost_units,
                    authority,
                )?;
            }
            invocation_count_after = current_count.saturating_add(1);
            total_cost_exposed_after = new_total_cost_exposed;
            total_cost_realized_spend_after = current_realized;
            event_seq = seq;
            usage_seq = Some(seq);
        } else {
            event_seq = allocate_budget_replication_seq(&transaction)?;
            invocation_count_after = current_count;
            total_cost_exposed_after = current_exposed;
            total_cost_realized_spend_after = current_realized;
            usage_seq = None;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::AuthorizeExposure,
            Some(allowed),
            event_seq,
            usage_seq,
            cost_units,
            0,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
        )?;
        transaction.commit()?;
        Ok(allowed)
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReverseExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units != cost_units || !hold.invocation_count_debited {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reverse amount"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

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
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, i64>(2)?.max(0) as u64,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count <= 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge larger than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - cost_units;
        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET invocation_count = ?3,
                updated_at = ?4,
                seq = ?5,
                total_cost_exposed = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                invocation_count - 1,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                )?
                .authority
                .as_ref(),
                authority,
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Reversed,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReverseExposure,
            None,
            seq,
            Some(seq),
            cost_units,
            0,
            None,
            None,
            None,
            (invocation_count - 1).max(0) as u32,
            new_total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReleaseExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units < cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` cannot release more than remaining exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

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
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, i64>(2)?.max(0) as u64,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if total_cost_exposed < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reduce charge larger than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - cost_units;
        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
            let remaining = hold.remaining_exposure_units - cost_units;
            let disposition = if remaining == 0 {
                HoldDisposition::Released
            } else {
                HoldDisposition::Open
            };
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                remaining,
                disposition,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReleaseExposure,
            None,
            seq,
            Some(seq),
            cost_units,
            0,
            None,
            None,
            None,
            invocation_count.max(0) as u32,
            new_total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
        )
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReconcileSpend,
            capability_id,
            grant_index,
            hold_id,
            authority,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units != exposed_cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reconciled exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

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
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, i64>(2)?.max(0) as u64,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count <= 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot settle charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < exposed_cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot settle more exposure than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - exposed_cost_units;
        let new_total_cost_realized_spend = total_cost_realized_spend
            .checked_add(realized_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total_cost_realized_spend + realized_cost_units overflowed u64".to_string(),
                )
            })?;

        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5,
                total_cost_realized_spend = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
                new_total_cost_realized_spend as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                )?
                .authority
                .as_ref(),
                authority,
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Reconciled,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReconcileSpend,
            None,
            seq,
            Some(seq),
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
            None,
            invocation_count.max(0) as u32,
            new_total_cost_exposed,
            new_total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
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
            WHERE (?1 IS NULL OR capability_id = ?1)
            ORDER BY updated_at DESC, capability_id ASC, grant_index ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![capability_id, limit as i64], record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.connection()?
            .query_row(
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
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
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
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR grant_index = ?2)
            ORDER BY event_seq ASC
            LIMIT ?3
            "#,
        )?;
        let rows = statement.query_map(
            params![
                capability_id,
                grant_index.map(|value| value as i64),
                limit as i64
            ],
            mutation_record_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn checked_committed_cost_units(
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
) -> Result<u64, BudgetStoreError> {
    total_cost_exposed
        .checked_add(total_cost_realized_spend)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "total_cost_exposed + total_cost_realized_spend overflowed u64".to_string(),
            )
        })
}

fn record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BudgetUsageRecord> {
    let total_cost_exposed = row.get::<_, i64>(5)?.max(0) as u64;
    let total_cost_realized_spend = row.get::<_, i64>(6)?.max(0) as u64;
    Ok(BudgetUsageRecord {
        capability_id: row.get(0)?,
        grant_index: row.get::<_, i64>(1)?.max(0) as u32,
        invocation_count: row.get::<_, i64>(2)?.max(0) as u32,
        updated_at: row.get(3)?,
        seq: row.get::<_, i64>(4)?.max(0) as u64,
        total_cost_exposed,
        total_cost_realized_spend,
    })
}

fn mutation_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BudgetMutationRecord> {
    let kind = row.get::<_, String>(4)?;
    let kind = BudgetMutationKind::parse(&kind).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown budget mutation kind `{kind}`"),
            )),
        )
    })?;
    let authority = sqlite_budget_event_authority(row.get(17)?, row.get(18)?, row.get(19)?)?;
    Ok(BudgetMutationRecord {
        event_id: row.get(0)?,
        hold_id: row.get(1)?,
        capability_id: row.get(2)?,
        grant_index: row.get::<_, i64>(3)?.max(0) as u32,
        kind,
        allowed: row.get::<_, Option<i64>>(5)?.map(|value| value > 0),
        recorded_at: row.get(6)?,
        event_seq: row.get::<_, i64>(7)?.max(0) as u64,
        usage_seq: row
            .get::<_, Option<i64>>(8)?
            .map(|value| value.max(0) as u64),
        exposure_units: row.get::<_, i64>(9)?.max(0) as u64,
        realized_spend_units: row.get::<_, i64>(10)?.max(0) as u64,
        max_invocations: row
            .get::<_, Option<i64>>(11)?
            .map(|value| value.max(0) as u32),
        max_cost_per_invocation: row
            .get::<_, Option<i64>>(12)?
            .map(|value| value.max(0) as u64),
        max_total_cost_units: row
            .get::<_, Option<i64>>(13)?
            .map(|value| value.max(0) as u64),
        invocation_count_after: row.get::<_, i64>(14)?.max(0) as u32,
        total_cost_exposed_after: row.get::<_, i64>(15)?.max(0) as u64,
        total_cost_realized_spend_after: row.get::<_, i64>(16)?.max(0) as u64,
        authority,
    })
}

fn sqlite_budget_event_authority(
    authority_id: Option<String>,
    lease_id: Option<String>,
    lease_epoch: Option<i64>,
) -> rusqlite::Result<Option<BudgetEventAuthority>> {
    match (authority_id, lease_id, lease_epoch) {
        (None, None, None) => Ok(None),
        (Some(authority_id), Some(lease_id), Some(lease_epoch)) if lease_epoch >= 0 => {
            Ok(Some(BudgetEventAuthority {
                authority_id,
                lease_id,
                lease_epoch: lease_epoch as u64,
            }))
        }
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid budget authority lease columns",
            )),
        )),
    }
}

fn ensure_budget_seq_column(connection: &Connection) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(capability_grant_budgets)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let has_seq = columns
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|column| column == "seq");
    if !has_seq {
        connection.execute(
            "ALTER TABLE capability_grant_budgets ADD COLUMN seq INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_capability_grant_budgets_seq ON capability_grant_budgets(seq)",
        [],
    )?;
    Ok(())
}

fn ensure_split_budget_cost_columns(connection: &Connection) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(capability_grant_budgets)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|c| c == "total_cost_exposed")
        || !columns.iter().any(|c| c == "total_cost_realized_spend")
    {
        return Err(BudgetStoreError::Invariant(
            "unsupported budget schema: missing split cost columns `total_cost_exposed` and `total_cost_realized_spend`".to_string(),
        ));
    }
    Ok(())
}

fn ensure_budget_hold_authority_columns(connection: &Connection) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_authorization_holds)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "authority_id") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN authority_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_id") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN lease_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_epoch") {
        connection.execute(
            "ALTER TABLE budget_authorization_holds ADD COLUMN lease_epoch INTEGER",
            [],
        )?;
    }
    Ok(())
}

fn ensure_budget_mutation_event_authority_columns(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_mutation_events)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "authority_id") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN authority_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_id") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN lease_id TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "lease_epoch") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN lease_epoch INTEGER",
            [],
        )?;
    }
    Ok(())
}

fn ensure_budget_mutation_event_seq_column(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(budget_mutation_events)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "event_seq") {
        connection.execute(
            "ALTER TABLE budget_mutation_events ADD COLUMN event_seq INTEGER",
            [],
        )?;
    }
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_budget_mutation_events_event_seq ON budget_mutation_events(event_seq)",
        [],
    )?;
    Ok(())
}

/// Initialize the replication sequence counter from existing rows on first open.
///
/// Uses an IMMEDIATE transaction, which acquires a write lock before any reads
/// or writes occur. In SQLite WAL mode, IMMEDIATE transactions are serialized:
/// concurrent reads can proceed, but no two processes can both hold IMMEDIATE
/// (or EXCLUSIVE) transactions simultaneously. This means two processes calling
/// `initialize_budget_replication_seq` concurrently will be serialized by
/// SQLite's locking protocol -- the second caller blocks until the first commits,
/// then runs with the updated seq floor already in place. No additional
/// application-level locking is required.
fn initialize_budget_replication_seq(connection: &mut Connection) -> Result<(), BudgetStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut next_seq = current_budget_replication_seq(&transaction)?
        .max(max_budget_usage_seq(&transaction)?)
        .max(max_budget_mutation_event_seq(&transaction)?);
    let mut statement = transaction.prepare(
        r#"
        SELECT rowid
        FROM capability_grant_budgets
        WHERE seq <= 0
        ORDER BY updated_at ASC, capability_id ASC, grant_index ASC
        "#,
    )?;
    let pending = statement
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for rowid in pending {
        next_seq = next_seq.saturating_add(1);
        transaction.execute(
            "UPDATE capability_grant_budgets SET seq = ?1 WHERE rowid = ?2",
            params![next_seq as i64, rowid],
        )?;
    }

    let existing_event_seq_count = transaction.query_row(
        "SELECT COUNT(*) FROM budget_mutation_events WHERE event_seq IS NOT NULL AND event_seq > 0",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    if existing_event_seq_count <= 0 {
        let mut statement = transaction.prepare(
            r#"
            SELECT rowid
            FROM budget_mutation_events
            ORDER BY rowid ASC
            "#,
        )?;
        let pending = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut event_seq = 0u64;
        for rowid in pending {
            event_seq = event_seq.saturating_add(1);
            transaction.execute(
                "UPDATE budget_mutation_events SET event_seq = ?1 WHERE rowid = ?2",
                params![event_seq as i64, rowid],
            )?;
        }
        next_seq = next_seq.max(event_seq);
    } else {
        let mut statement = transaction.prepare(
            r#"
            SELECT rowid
            FROM budget_mutation_events
            WHERE event_seq IS NULL OR event_seq <= 0
            ORDER BY rowid ASC
            "#,
        )?;
        let pending = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for rowid in pending {
            next_seq = next_seq.saturating_add(1);
            transaction.execute(
                "UPDATE budget_mutation_events SET event_seq = ?1 WHERE rowid = ?2",
                params![next_seq as i64, rowid],
            )?;
        }
    }
    set_budget_replication_seq(&transaction, next_seq)?;
    transaction.commit()?;
    Ok(())
}

fn allocate_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let current = current_budget_replication_seq(transaction)?
        .max(max_budget_usage_seq(transaction)?)
        .max(max_budget_mutation_event_seq(transaction)?);
    let next_seq = current.saturating_add(1);
    set_budget_replication_seq(transaction, next_seq)?;
    Ok(next_seq)
}

fn raise_budget_replication_seq_floor(
    transaction: &rusqlite::Transaction<'_>,
    seq: u64,
) -> Result<(), BudgetStoreError> {
    let current = current_budget_replication_seq(transaction)?;
    if seq > current {
        set_budget_replication_seq(transaction, seq)?;
    }
    Ok(())
}

fn current_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let next_seq = transaction.query_row(
        "SELECT next_seq FROM budget_replication_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(next_seq.max(0) as u64)
}

fn max_budget_usage_seq(transaction: &rusqlite::Transaction<'_>) -> Result<u64, BudgetStoreError> {
    let max_seq = transaction.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM capability_grant_budgets",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(max_seq.max(0) as u64)
}

fn max_budget_mutation_event_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let max_seq = transaction.query_row(
        "SELECT COALESCE(MAX(event_seq), 0) FROM budget_mutation_events",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(max_seq.max(0) as u64)
}

fn set_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
    seq: u64,
) -> Result<(), BudgetStoreError> {
    transaction.execute(
        "UPDATE budget_replication_meta SET next_seq = ?1 WHERE singleton = 1",
        params![seq as i64],
    )?;
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_kernel::InMemoryBudgetStore;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn usage_record(
        capability_id: &str,
        grant_index: u32,
        invocation_count: u32,
        updated_at: i64,
        seq: u64,
        total_cost_exposed: u64,
        total_cost_realized_spend: u64,
    ) -> BudgetUsageRecord {
        BudgetUsageRecord {
            capability_id: capability_id.to_string(),
            grant_index,
            invocation_count,
            updated_at,
            seq,
            total_cost_exposed,
            total_cost_realized_spend,
        }
    }

    fn assert_usage_totals(record: &BudgetUsageRecord, exposed: u64, realized: u64) {
        assert_eq!(record.total_cost_exposed, exposed);
        assert_eq!(record.total_cost_realized_spend, realized);
        assert_eq!(record.committed_cost_units().unwrap(), exposed + realized);
    }

    fn authority(authority_id: &str, lease_id: &str, lease_epoch: u64) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: authority_id.to_string(),
            lease_id: lease_id.to_string(),
            lease_epoch,
        }
    }

    #[test]
    fn sqlite_budget_store_persists_across_reopen() {
        let path = unique_db_path("chio-budgets");
        {
            let store = SqliteBudgetStore::open(&path).unwrap();
            assert!(store.try_increment("cap-1", 0, Some(2)).unwrap());
            assert!(store.try_increment("cap-1", 0, Some(2)).unwrap());
            assert!(!store.try_increment("cap-1", 0, Some(2)).unwrap());
        }

        let reopened = SqliteBudgetStore::open(&path).unwrap();
        let records = reopened.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].invocation_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_budget_store_rejects_pre_split_budget_schema() {
        let path = unique_db_path("chio-budget-pre-split-schema");
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    r#"
                    CREATE TABLE capability_grant_budgets (
                        capability_id TEXT NOT NULL,
                        grant_index INTEGER NOT NULL,
                        invocation_count INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        total_cost_charged INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (capability_id, grant_index)
                    );
                    INSERT INTO capability_grant_budgets (
                        capability_id,
                        grant_index,
                        invocation_count,
                        updated_at,
                        total_cost_charged
                    ) VALUES ('cap-1', 0, 1, 10, 55);
                    "#,
                )
                .unwrap();
        }

        let error = match SqliteBudgetStore::open(&path) {
            Ok(_) => panic!("pre-split budget schema should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(
            "missing split cost columns `total_cost_exposed` and `total_cost_realized_spend`"
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_budget_store_upsert_usage_keeps_newer_seq_state() {
        let path = unique_db_path("chio-budget-upsert");
        let store = SqliteBudgetStore::open(&path).unwrap();
        store
            .upsert_usage(&usage_record("cap-1", 0, 3, 10, 3, 300, 0))
            .unwrap();
        store
            .upsert_usage(&usage_record("cap-1", 0, 2, 9, 2, 200, 0))
            .unwrap();

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].invocation_count, 3);
        assert_usage_totals(&records[0], 300, 0);
        assert_eq!(records[0].seq, 3);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_budget_store_uses_seq_for_same_key_delta_queries() {
        let path = unique_db_path("chio-budget-seq-delta");
        let store = SqliteBudgetStore::open(&path).unwrap();

        assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
        let first = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(first.len(), 1);
        let first_seq = first[0].seq;

        assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
        assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

        let delta = store.list_usages_after(10, Some(first_seq)).unwrap();
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].invocation_count, 3);
        assert!(delta[0].seq > first_seq);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_budget_store_preserves_imported_seq_across_failover_writes() {
        let path = unique_db_path("chio-budget-seq-floor");
        let store = SqliteBudgetStore::open(&path).unwrap();

        store
            .upsert_usage(&usage_record("cap-1", 0, 3, 10, 42, 0, 0))
            .unwrap();
        assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].invocation_count, 4);
        assert_eq!(records[0].seq, 43);

        let _ = fs::remove_file(path);
    }

    // --- try_charge_cost tests ---

    #[test]
    fn budget_store_try_charge_cost_within_limits_returns_true_sqlite() {
        let path = unique_db_path("chio-charge-cost-ok");
        let store = SqliteBudgetStore::open(&path).unwrap();
        // 100 units, cap is 200 per invocation, total cap is 1000
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap();
        assert!(ok);

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].invocation_count, 1);
        assert_usage_totals(&records[0], 100, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_try_charge_cost_exceeds_per_invocation_cap_sqlite() {
        let path = unique_db_path("chio-charge-cost-per-inv");
        let store = SqliteBudgetStore::open(&path).unwrap();
        // 500 units > max_cost_per_invocation of 200
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
            .unwrap();
        assert!(!ok);

        // Nothing should have been charged
        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert!(records.is_empty() || records[0].invocation_count == 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_try_charge_cost_exceeds_total_cap_sqlite() {
        let path = unique_db_path("chio-charge-cost-total");
        let store = SqliteBudgetStore::open(&path).unwrap();
        // First charge 900 of 1000 budget
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
            .unwrap());
        // Second charge of 200 would exceed the total cap of 1000
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
            .unwrap();
        assert!(!ok);

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_usage_totals(&records[0], 900, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_try_charge_cost_atomic_increment_sqlite() {
        let path = unique_db_path("chio-charge-cost-atomic");
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .try_charge_cost("cap-1", 0, None, 100, Some(200), Some(1000))
            .unwrap());
        assert!(store
            .try_charge_cost("cap-1", 0, None, 150, Some(200), Some(1000))
            .unwrap());

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].invocation_count, 2);
        assert_usage_totals(&records[0], 250, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_try_charge_cost_within_limits_returns_true_inmemory() {
        let store = InMemoryBudgetStore::new();
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap();
        assert!(ok);

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_eq!(records[0].invocation_count, 1);
        assert_usage_totals(&records[0], 100, 0);
    }

    #[test]
    fn budget_store_try_charge_cost_exceeds_per_invocation_cap_inmemory() {
        let store = InMemoryBudgetStore::new();
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
            .unwrap();
        assert!(!ok);
    }

    #[test]
    fn budget_store_try_charge_cost_exceeds_total_cap_inmemory() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
            .unwrap());
        let ok = store
            .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
            .unwrap();
        assert!(!ok);
    }

    #[test]
    fn budget_usage_record_includes_split_cost_state() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-1", 0, None, 42, None, None)
            .unwrap());
        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_usage_totals(&records[0], 42, 0);
    }

    #[test]
    fn budget_store_reverse_charge_cost_restores_prior_state_inmemory() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.reverse_charge_cost("cap-1", 0, 100).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 0);
        assert_usage_totals(&record, 0, 0);
    }

    #[test]
    fn budget_store_reverse_charge_cost_restores_prior_state_sqlite() {
        let path = unique_db_path("chio-reverse-charge");
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.reverse_charge_cost("cap-1", 0, 100).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 0);
        assert_usage_totals(&record, 0, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_reduce_charge_cost_releases_exposure_only_inmemory() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.reduce_charge_cost("cap-1", 0, 25).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 1);
        assert_usage_totals(&record, 75, 0);
    }

    #[test]
    fn budget_store_reduce_charge_cost_releases_exposure_only_sqlite() {
        let path = unique_db_path("chio-reduce-charge");
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.reduce_charge_cost("cap-1", 0, 25).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 1);
        assert_usage_totals(&record, 75, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_settle_charge_cost_moves_exposure_to_realized_inmemory() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 1);
        assert_usage_totals(&record, 0, 75);
    }

    #[test]
    fn budget_store_settle_charge_cost_moves_exposure_to_realized_sqlite() {
        let path = unique_db_path("chio-settle-charge");
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
            .unwrap());

        store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

        let record = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(record.invocation_count, 1);
        assert_usage_totals(&record, 0, 75);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_try_charge_cost_with_ids_is_idempotent_inmemory() {
        let store = InMemoryBudgetStore::new();
        let hold_id = "hold-cap-1-0";
        let event_id = "hold-cap-1-0:authorize";

        assert!(store
            .try_charge_cost_with_ids(
                "cap-1",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
            )
            .unwrap());
        assert!(store
            .try_charge_cost_with_ids(
                "cap-1",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
            )
            .unwrap());

        let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_usage_totals(&usage, 100, 0);

        let events = store
            .list_mutation_events(10, Some("cap-1"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, event_id);
        assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
        assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
        assert_eq!(events[0].allowed, Some(true));
    }

    #[test]
    fn budget_store_try_charge_cost_with_ids_is_idempotent_sqlite() {
        let path = unique_db_path("chio-charge-cost-idempotent");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let hold_id = "hold-cap-1-0";
        let event_id = "hold-cap-1-0:authorize";

        assert!(store
            .try_charge_cost_with_ids(
                "cap-1",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
            )
            .unwrap());
        assert!(store
            .try_charge_cost_with_ids(
                "cap-1",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
            )
            .unwrap());

        let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_usage_totals(&usage, 100, 0);

        let events = store
            .list_mutation_events(10, Some("cap-1"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, event_id);
        assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
        assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
        assert_eq!(events[0].allowed, Some(true));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_settle_with_ids_is_idempotent_and_append_only_sqlite() {
        let path = unique_db_path("chio-settle-charge-idempotent");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let hold_id = "hold-cap-1-0";
        let authorize_event_id = "hold-cap-1-0:authorize";
        let reconcile_event_id = "hold-cap-1-0:reconcile";

        assert!(store
            .try_charge_cost_with_ids(
                "cap-1",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(authorize_event_id),
            )
            .unwrap());
        store
            .settle_charge_cost_with_ids(
                "cap-1",
                0,
                100,
                75,
                Some(hold_id),
                Some(reconcile_event_id),
            )
            .unwrap();
        store
            .settle_charge_cost_with_ids(
                "cap-1",
                0,
                100,
                75,
                Some(hold_id),
                Some(reconcile_event_id),
            )
            .unwrap();

        let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_usage_totals(&usage, 0, 75);

        let events = store
            .list_mutation_events(10, Some("cap-1"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, authorize_event_id);
        assert_eq!(events[1].event_id, reconcile_event_id);
        assert_eq!(events[1].hold_id.as_deref(), Some(hold_id));
        assert_eq!(events[1].kind, BudgetMutationKind::ReconcileSpend);
        assert_eq!(events[1].exposure_units, 100);
        assert_eq!(events[1].realized_spend_units, 75);
        assert_eq!(events[1].total_cost_exposed_after, 0);
        assert_eq!(events[1].total_cost_realized_spend_after, 75);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_reduce_charge_cost_allows_zero_invocation_release_sqlite() {
        let path = unique_db_path("chio-reduce-charge-zero-invocations");
        let store = SqliteBudgetStore::open(&path).unwrap();
        store
            .upsert_usage(&usage_record("cap-zero", 0, 0, 10, 10, 40, 0))
            .unwrap();

        store.reduce_charge_cost("cap-zero", 0, 25).unwrap();

        let usage = store.get_usage("cap-zero", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 0);
        assert_usage_totals(&usage, 15, 0);

        let events = store
            .list_mutation_events(10, Some("cap-zero"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, BudgetMutationKind::ReleaseExposure);
        assert_eq!(events[0].invocation_count_after, 0);
        assert_eq!(events[0].total_cost_exposed_after, 15);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_list_mutation_events_preserves_append_order_sqlite() {
        let path = unique_db_path("chio-budget-event-order");
        let store = SqliteBudgetStore::open(&path).unwrap();

        assert!(store
            .try_charge_cost_with_ids(
                "cap-order",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some("hold-cap-order-0"),
                Some("z-authorize"),
            )
            .unwrap());
        store
            .reduce_charge_cost_with_ids(
                "cap-order",
                0,
                25,
                Some("hold-cap-order-0"),
                Some("a-release"),
            )
            .unwrap();

        let events = store
            .list_mutation_events(10, Some("cap-order"), Some(0))
            .unwrap();
        let event_ids = events
            .iter()
            .map(|record| record.event_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(event_ids, vec!["z-authorize", "a-release"]);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_hold_authority_requires_exact_lease_inmemory() {
        let store = InMemoryBudgetStore::new();
        let hold_id = "hold-cap-lease-0";
        let authorize_event_id = "hold-cap-lease-0:authorize";
        let release_event_id = "hold-cap-lease-0:release";
        let reconcile_event_id = "hold-cap-lease-0:reconcile";
        let initial = authority("budget-primary", "lease-7", 7);
        let advanced = authority("budget-primary", "lease-7", 8);
        let stale = authority("budget-primary", "lease-7", 6);

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(authorize_event_id),
                Some(&initial),
            )
            .unwrap());

        let missing = store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                25,
                Some(hold_id),
                Some("hold-cap-lease-0:release-missing"),
                None,
            )
            .expect_err("missing lease metadata should fail closed");
        assert!(missing
            .to_string()
            .contains("requires authority lease metadata"));

        let stale_error = store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                25,
                Some(hold_id),
                Some("hold-cap-lease-0:release-stale"),
                Some(&stale),
            )
            .expect_err("stale lease epoch should fail closed");
        assert!(stale_error.to_string().contains("lease epoch regressed"));

        let advanced_error = store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                25,
                Some(hold_id),
                Some(release_event_id),
                Some(&advanced),
            )
            .expect_err("advanced lease epoch should fail closed");
        assert!(advanced_error
            .to_string()
            .contains("advanced beyond the open lease"));

        store
            .reduce_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                25,
                Some(hold_id),
                Some(release_event_id),
                Some(&initial),
            )
            .unwrap();
        store
            .settle_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                75,
                75,
                Some(hold_id),
                Some(reconcile_event_id),
                Some(&initial),
            )
            .unwrap();

        let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_usage_totals(&usage, 0, 75);

        let events = store
            .list_mutation_events(10, Some("cap-lease"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].authority.as_ref(), Some(&initial));
        assert_eq!(events[1].authority.as_ref(), Some(&initial));
        assert_eq!(events[2].authority.as_ref(), Some(&initial));
    }

    #[test]
    fn budget_store_event_id_reuse_rejects_authority_rollover_sqlite() {
        let path = unique_db_path("chio-hold-authority-event-reuse");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let hold_id = "hold-cap-lease-0";
        let event_id = "hold-cap-lease-0:authorize";
        let initial = authority("budget-primary", "lease-7", 7);
        let changed = authority("budget-primary", "lease-8", 8);

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
                Some(&initial),
            )
            .unwrap());

        let error = store
            .try_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
                Some(&changed),
            )
            .expect_err("reused event id with different authority should fail closed");
        assert!(error
            .to_string()
            .contains("was reused for a different mutation"));

        let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_usage_totals(&usage, 100, 0);

        let events = store
            .list_mutation_events(10, Some("cap-lease"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].authority.as_ref(), Some(&initial));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_deleted_provisional_event_allows_retry_after_compensation_sqlite() {
        let path = unique_db_path("chio-hold-authority-compensation");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let hold_id = "hold-cap-lease-0";
        let event_id = "hold-cap-lease-0:authorize";
        let initial = authority("budget-primary", "lease-7", 7);
        let changed = authority("budget-primary", "lease-8", 8);

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
                Some(&initial),
            )
            .unwrap());
        store
            .reverse_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                100,
                Some(hold_id),
                Some("hold-cap-lease-0:authorize:rollback"),
                Some(&initial),
            )
            .unwrap();
        store.delete_hold(hold_id).unwrap();
        store.delete_mutation_event(event_id).unwrap();

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
                Some(&changed),
            )
            .unwrap());

        let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_usage_totals(&usage, 100, 0);

        let events = store
            .list_mutation_events(10, Some("cap-lease"), Some(0))
            .unwrap();
        let event_ids = events
            .iter()
            .map(|record| record.event_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            event_ids,
            vec![
                "hold-cap-lease-0:authorize:rollback",
                "hold-cap-lease-0:authorize"
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_rollback_artifact_allows_retry_with_new_authority_sqlite() {
        let path = unique_db_path("chio-hold-authority-rollback-retry");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let hold_id = "hold-cap-lease-0";
        let event_id = "hold-cap-lease-0:authorize";
        let rollback_event_id = "hold-cap-lease-0:authorize:rollback:2";
        let initial = authority("budget-primary", "lease-7", 7);
        let changed = authority("budget-primary", "lease-8", 8);

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
                Some(&initial),
            )
            .unwrap());
        store
            .reverse_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                100,
                Some(hold_id),
                Some(rollback_event_id),
                Some(&initial),
            )
            .unwrap();

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-lease",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
                Some(&changed),
            )
            .unwrap());

        let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_usage_totals(&usage, 100, 0);

        let events = store
            .list_mutation_events(10, Some("cap-lease"), Some(0))
            .unwrap();
        let authorize = events
            .iter()
            .find(|record| record.event_id == event_id)
            .expect("replacement authorize event");
        assert_eq!(authorize.authority.as_ref(), Some(&changed));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_retry_after_rollback_replaces_orphaned_open_hold_sqlite() {
        let path = unique_db_path("chio-hold-rollback-orphan-retry");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let hold_id = "hold-cap-orphan-0";
        let event_id = "hold-cap-orphan-0:authorize";
        let rollback_event_id = "hold-cap-orphan-0:authorize:rollback:5";
        let initial = authority("budget-primary", "lease-7", 7);
        let changed = authority("budget-primary", "lease-8", 8);

        for _ in 0..3 {
            assert!(store
                .try_increment_with_event_id("cap-orphan", 0, Some(10), None)
                .unwrap());
        }
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-orphan",
                0,
                Some(10),
                75,
                Some(100),
                Some(400),
                Some(hold_id),
                Some(event_id),
                Some(&initial),
            )
            .unwrap());
        store
            .reverse_charge_cost_with_ids_and_authority(
                "cap-orphan",
                0,
                75,
                Some(hold_id),
                Some(rollback_event_id),
                Some(&initial),
            )
            .unwrap();

        {
            let mut connection = store.connection().unwrap();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            transaction
                .execute(
                    "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                    params![event_id],
                )
                .unwrap();
            SqliteBudgetStore::upsert_hold(
                &transaction,
                hold_id,
                "cap-orphan",
                0,
                75,
                75,
                HoldDisposition::Open,
                Some(&initial),
            )
            .unwrap();
            transaction.commit().unwrap();
        }

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-orphan",
                0,
                Some(10),
                75,
                Some(100),
                Some(400),
                Some(hold_id),
                Some(event_id),
                Some(&changed),
            )
            .unwrap());

        let usage = store.get_usage("cap-orphan", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 4);
        assert_usage_totals(&usage, 75, 0);

        let events = store
            .list_mutation_events(20, Some("cap-orphan"), Some(0))
            .unwrap();
        let rollback = events
            .iter()
            .find(|record| record.event_id == rollback_event_id)
            .expect("rollback event");
        let retry = events
            .iter()
            .find(|record| record.event_id == event_id)
            .expect("retry authorize event");
        assert!(retry.event_seq > rollback.event_seq);
        assert_eq!(retry.authority.as_ref(), Some(&changed));

        {
            let mut connection = store.connection().unwrap();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
                .unwrap()
                .expect("retry open hold");
            assert_eq!(hold.remaining_exposure_units, 75);
            assert_eq!(hold.disposition, HoldDisposition::Open);
        }

        {
            let mut connection = store.connection().unwrap();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            transaction
                .execute(
                    "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                    params![event_id],
                )
                .unwrap();
            transaction.commit().unwrap();
        }

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-orphan",
                0,
                Some(10),
                75,
                Some(100),
                Some(400),
                Some(hold_id),
                Some(event_id),
                Some(&changed),
            )
            .unwrap());
        let events = store
            .list_mutation_events(20, Some("cap-orphan"), Some(0))
            .unwrap();
        let replayed_retry = events
            .iter()
            .find(|record| record.event_id == event_id)
            .expect("replayed retry authorize event");
        assert_eq!(replayed_retry.allowed, Some(true));
        assert_eq!(replayed_retry.usage_seq, Some(usage.seq));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn import_mutation_record_keeps_duplicate_release_events_idempotent_sqlite() {
        let path = unique_db_path("chio-budget-import-release-idempotent");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let hold_id = "hold-cap-import-0";
        let authorize_event_id = "hold-cap-import-0:authorize";
        let release_event_id = "hold-cap-import-0:release";

        assert!(store
            .try_charge_cost_with_ids(
                "cap-import",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(authorize_event_id),
            )
            .unwrap());
        store
            .reduce_charge_cost_with_ids(
                "cap-import",
                0,
                100,
                Some(hold_id),
                Some(release_event_id),
            )
            .unwrap();

        let release_record = store
            .list_mutation_events(10, Some("cap-import"), Some(0))
            .unwrap()
            .into_iter()
            .find(|record| record.event_id == release_event_id)
            .expect("release event record");

        store.import_mutation_record(&release_record).unwrap();

        let usage = store.get_usage("cap-import", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_usage_totals(&usage, 0, 0);

        {
            let mut connection = store.connection().unwrap();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
                .unwrap()
                .expect("released hold state");
            assert_eq!(hold.remaining_exposure_units, 0);
            assert_eq!(hold.disposition, HoldDisposition::Released);
        }

        let events = store
            .list_mutation_events(10, Some("cap-import"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, authorize_event_id);
        assert_eq!(events[1].event_id, release_event_id);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn import_snapshot_records_replay_is_idempotent_when_peer_cursor_is_lost_sqlite() {
        let source_path = unique_db_path("chio-budget-import-replay-source");
        let target_path = unique_db_path("chio-budget-import-replay-target");
        let source = SqliteBudgetStore::open(&source_path).unwrap();

        assert!(source
            .try_charge_cost_with_ids(
                "cap-import-replay",
                0,
                Some(5),
                25,
                Some(50),
                Some(250),
                Some("hold-import-replay-0"),
                Some("hold-import-replay-0:authorize"),
            )
            .unwrap());
        let usage = source
            .get_usage("cap-import-replay", 0)
            .unwrap()
            .expect("source usage");
        let events = source
            .list_mutation_events(10, Some("cap-import-replay"), Some(0))
            .unwrap();

        let target = SqliteBudgetStore::open(&target_path).unwrap();
        target
            .import_snapshot_records(std::slice::from_ref(&usage), &events)
            .unwrap();
        target
            .import_snapshot_records(std::slice::from_ref(&usage), &events)
            .unwrap();

        let replicated_usage = target
            .get_usage("cap-import-replay", 0)
            .unwrap()
            .expect("replicated usage");
        assert_eq!(replicated_usage.invocation_count, 1);
        assert_usage_totals(&replicated_usage, 25, 0);
        let replicated_events = target
            .list_mutation_events(10, Some("cap-import-replay"), Some(0))
            .unwrap();
        assert_eq!(replicated_events.len(), 1);
        assert_eq!(
            replicated_events[0].event_id,
            "hold-import-replay-0:authorize"
        );

        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(target_path);
    }

    #[test]
    fn import_snapshot_records_rolls_back_usage_rows_when_mutation_conflicts_sqlite() {
        let path = unique_db_path("chio-budget-import-atomic");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let initial_authority = authority("budget-primary", "lease-1", 1);
        let conflicting_authority = authority("budget-primary", "lease-2", 2);

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-import",
                0,
                Some(10),
                25,
                Some(100),
                Some(500),
                Some("hold-cap-import-atomic-0"),
                Some("hold-cap-import-atomic-0:authorize"),
                Some(&initial_authority),
            )
            .unwrap());

        let mut conflicting_event = store
            .list_mutation_events(10, Some("cap-import"), Some(0))
            .unwrap()
            .into_iter()
            .find(|record| record.event_id == "hold-cap-import-atomic-0:authorize")
            .expect("existing authorize event");
        conflicting_event.authority = Some(conflicting_authority);

        let imported_usage = usage_record("cap-import-rollback", 0, 2, unix_now(), 88, 40, 5);

        let error = store
            .import_snapshot_records(&[imported_usage], &[conflicting_event])
            .expect_err("conflicting event import should fail atomically");
        assert!(error
            .to_string()
            .contains("reused for a different mutation"));
        assert!(store.get_usage("cap-import-rollback", 0).unwrap().is_none());

        let existing = store.get_usage("cap-import", 0).unwrap().unwrap();
        assert_eq!(existing.invocation_count, 1);
        assert_usage_totals(&existing, 25, 0);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_open_hold_recovers_missing_authorize_event_sqlite() {
        let path = unique_db_path("chio-hold-authority-recover-missing-event");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let hold_id = "hold-cap-recover-0";
        let event_id = "hold-cap-recover-0:authorize";
        let authority = authority("budget-primary", "lease-7", 7);

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-recover",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
                Some(&authority),
            )
            .unwrap());
        store.delete_mutation_event(event_id).unwrap();

        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-recover",
                0,
                Some(10),
                100,
                Some(200),
                Some(1000),
                Some(hold_id),
                Some(event_id),
                Some(&authority),
            )
            .unwrap());

        let events = store
            .list_mutation_events(10, Some("cap-recover"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, event_id);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn upsert_usage_preserves_newer_split_cost_state() {
        let path = unique_db_path("chio-budget-upsert-cost");
        let store = SqliteBudgetStore::open(&path).unwrap();

        // Higher-seq record written first
        store
            .upsert_usage(&usage_record("cap-1", 0, 5, 10, 10, 500, 0))
            .unwrap();

        // Lower-seq record written second (stale replica)
        store
            .upsert_usage(&usage_record("cap-1", 0, 3, 12, 5, 300, 0))
            .unwrap();

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_usage_totals(&records[0], 500, 0);
        assert_eq!(records[0].seq, 10);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn upsert_usage_does_not_resurrect_split_cost_state_from_stale_seq() {
        let path = unique_db_path("chio-budget-upsert-split");
        let store = SqliteBudgetStore::open(&path).unwrap();

        store
            .upsert_usage(&usage_record("cap-1", 0, 1, 20, 20, 0, 75))
            .unwrap();
        store
            .upsert_usage(&usage_record("cap-1", 0, 1, 10, 10, 100, 0))
            .unwrap();

        let records = store.list_usages(10, Some("cap-1")).unwrap();
        assert_usage_totals(&records[0], 0, 75);
        assert_eq!(records[0].seq, 20);

        let _ = fs::remove_file(path);
    }

    /// Documents the HA overrun bound for monetary budget enforcement.
    ///
    /// In a split-brain scenario across N nodes, each node may independently
    /// approve one invocation at max_cost_per_invocation before the LWW merge
    /// propagates. The worst-case overrun is bounded by:
    ///   overrun <= max_cost_per_invocation * node_count
    ///
    /// This test asserts the bound holds for a simulated 2-node split-brain.
    #[test]
    fn concurrent_charge_overrun_bound() {
        let path_a = unique_db_path("chio-overrun-node-a");
        let path_b = unique_db_path("chio-overrun-node-b");

        let max_per_invocation: u64 = 100;
        let total_budget: u64 = 150; // Tight: allows 1 full invocation + small buffer
        let node_count: u64 = 2;

        // Both nodes start fresh (simulating split-brain: neither sees the other's write)
        let node_a = SqliteBudgetStore::open(&path_a).unwrap();
        let node_b = SqliteBudgetStore::open(&path_b).unwrap();

        // Both nodes independently approve an invocation of max_per_invocation
        let approved_a = node_a
            .try_charge_cost(
                "cap-split",
                0,
                None,
                max_per_invocation,
                Some(max_per_invocation),
                Some(total_budget),
            )
            .unwrap();
        let approved_b = node_b
            .try_charge_cost(
                "cap-split",
                0,
                None,
                max_per_invocation,
                Some(max_per_invocation),
                Some(total_budget),
            )
            .unwrap();

        // Both nodes approved (split-brain; each sees a fresh slate)
        assert!(approved_a, "node A should approve");
        assert!(approved_b, "node B should approve");

        // The actual combined spend exceeds the total budget
        let combined_spend = max_per_invocation * node_count;
        // The overrun is bounded by max_cost_per_invocation * node_count
        let max_overrun = max_per_invocation * node_count;
        assert!(
            combined_spend <= max_overrun,
            "HA overrun bound violated: combined_spend={combined_spend} > max_overrun={max_overrun}"
        );

        // After LWW merge converges, outstanding exposure remains conservatively bounded.
        let record_a = node_a.list_usages(1, Some("cap-split")).unwrap();
        let record_b = node_b.list_usages(1, Some("cap-split")).unwrap();
        let total_after_merge = record_a[0].total_cost_exposed + record_b[0].total_cost_exposed;
        assert!(
            total_after_merge <= max_overrun,
            "post-merge total {total_after_merge} exceeds bound {max_overrun}"
        );

        let _ = fs::remove_file(path_a);
        let _ = fs::remove_file(path_b);
    }

    #[test]
    fn budget_store_zero_max_total_denies_any_charge_inmemory() {
        // A grant with max_total_cost = 0 must deny even a charge of 1 unit.
        let store = InMemoryBudgetStore::new();
        let ok = store
            .try_charge_cost("cap-zero-budget", 0, None, 1, None, Some(0))
            .unwrap();
        assert!(
            !ok,
            "any charge against a zero-unit total budget must be denied"
        );
        let records = store.list_usages(10, Some("cap-zero-budget")).unwrap();
        assert!(
            records.is_empty() || records[0].invocation_count == 0,
            "no invocations should be recorded against a zero-unit budget"
        );
    }

    #[test]
    fn budget_store_zero_max_total_denies_any_charge_sqlite() {
        let path = unique_db_path("chio-zero-budget-sqlite");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let ok = store
            .try_charge_cost("cap-zero-budget", 0, None, 1, None, Some(0))
            .unwrap();
        assert!(
            !ok,
            "any charge against a zero-unit total budget must be denied"
        );
        let records = store.list_usages(10, Some("cap-zero-budget")).unwrap();
        assert!(
            records.is_empty() || records[0].invocation_count == 0,
            "no invocations should be recorded against a zero-unit budget"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_store_zero_cost_invocation_succeeds_and_records_zero_inmemory() {
        // A zero-cost invocation against a monetary grant should succeed and
        // record cost_charged = 0.
        let store = InMemoryBudgetStore::new();
        let ok = store
            .try_charge_cost("cap-zero-cost", 0, None, 0, None, Some(1000))
            .unwrap();
        assert!(
            ok,
            "zero-cost invocation should succeed when budget is available"
        );
        let records = store.list_usages(10, Some("cap-zero-cost")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].invocation_count, 1);
        assert_usage_totals(&records[0], 0, 0);
    }

    #[test]
    fn budget_store_zero_cost_invocation_succeeds_and_records_zero_sqlite() {
        let path = unique_db_path("chio-zero-cost-sqlite");
        let store = SqliteBudgetStore::open(&path).unwrap();
        let ok = store
            .try_charge_cost("cap-zero-cost", 0, None, 0, None, Some(1000))
            .unwrap();
        assert!(
            ok,
            "zero-cost invocation should succeed when budget is available"
        );
        let records = store.list_usages(10, Some("cap-zero-cost")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].invocation_count, 1);
        assert_usage_totals(&records[0], 0, 0);
        let _ = fs::remove_file(path);
    }
}
