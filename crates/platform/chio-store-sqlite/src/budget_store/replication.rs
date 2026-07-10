use super::*;

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
pub(super) fn initialize_budget_replication_seq(
    connection: &mut Connection,
) -> Result<(), BudgetStoreError> {
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
            params![
                budget_sqlite_i64(next_seq, "budget replication sequence")?,
                rowid
            ],
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
                params![
                    budget_sqlite_i64(event_seq, "budget event sequence")?,
                    rowid
                ],
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
                params![
                    budget_sqlite_i64(next_seq, "budget replication sequence")?,
                    rowid
                ],
            )?;
        }
    }
    set_budget_replication_seq(&transaction, next_seq)?;
    transaction.commit()?;
    Ok(())
}

pub(super) fn allocate_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let current = current_budget_replication_seq(transaction)?
        .max(max_budget_usage_seq(transaction)?)
        .max(max_budget_mutation_event_seq(transaction)?);
    let next_seq = current.saturating_add(1);
    set_budget_replication_seq(transaction, next_seq)?;
    Ok(next_seq)
}

pub(super) fn raise_budget_replication_seq_floor(
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
        |row| budget_u64_from_row(row, 0, "next_seq"),
    )?;
    Ok(next_seq)
}

fn max_budget_usage_seq(transaction: &rusqlite::Transaction<'_>) -> Result<u64, BudgetStoreError> {
    let max_seq = transaction.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM capability_grant_budgets",
        [],
        |row| budget_u64_from_row(row, 0, "seq"),
    )?;
    Ok(max_seq)
}

fn max_budget_mutation_event_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let max_seq = transaction.query_row(
        "SELECT COALESCE(MAX(event_seq), 0) FROM budget_mutation_events",
        [],
        |row| budget_u64_from_row(row, 0, "event_seq"),
    )?;
    Ok(max_seq)
}

fn set_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
    seq: u64,
) -> Result<(), BudgetStoreError> {
    transaction.execute(
        "UPDATE budget_replication_meta SET next_seq = ?1 WHERE singleton = 1",
        params![budget_sqlite_i64(seq, "budget replication sequence")?],
    )?;
    Ok(())
}

pub(super) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
