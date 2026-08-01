use super::*;

/// Quorum-witness identity of a stored budget mutation event: its `event_seq`,
/// origin `authority_id`, and origin `lease_epoch`.
pub type BudgetEventWitness = (u64, Option<String>, Option<u64>);

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
            params![budget_u64_to_sqlite(next_seq, "seq")?, rowid],
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
                params![budget_u64_to_sqlite(event_seq, "event_seq")?, rowid],
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
                params![budget_u64_to_sqlite(next_seq, "event_seq")?, rowid],
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
        params![budget_u64_to_sqlite(seq, "next_seq")?],
    )?;
    Ok(())
}

impl SqliteBudgetStore {
    /// Highest budget mutation event_seq, or 0 when empty. Mirrors the private
    /// max_budget_mutation_event_seq helper but is a public head read for the
    /// status path.
    pub fn max_mutation_event_seq(&self) -> Result<u64, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let seq = transaction.query_row(
            "SELECT COALESCE(MAX(event_seq), 0) FROM budget_mutation_events",
            [],
            |row| budget_u64_from_row(row, 0, "event_seq"),
        )?;
        transaction.rollback()?;
        Ok(seq)
    }

    /// Highest mutation event_seq written under one origin authority, or 0 when
    /// none. The cluster budget-write handler reads this immediately after a
    /// local (leader) write to build the write's quorum-witness token: it is
    /// always >= the just-written event's own seq (a concurrent same-origin
    /// write can only raise it), so the per-origin contiguous witness can only
    /// under-count witnesses, never over-count one (fail-closed).
    pub fn max_mutation_event_seq_for_authority(
        &self,
        authority_id: &str,
    ) -> Result<u64, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let seq = transaction.query_row(
            "SELECT COALESCE(MAX(event_seq), 0) FROM budget_mutation_events WHERE authority_id = ?1",
            rusqlite::params![authority_id],
            |row| budget_u64_from_row(row, 0, "event_seq"),
        )?;
        transaction.rollback()?;
        Ok(seq)
    }

    /// The exact event_seq of the mutation event written under `event_id`, or
    /// None if no such event exists (or it predates seq assignment). The
    /// cluster budget-write handler waits on THIS write's own event_seq, looked
    /// up by the write's event_id, instead of MAX(event_seq) for the authority:
    /// a concurrent same-authority commit (or an idempotent retry while later
    /// same-origin events already exist) can raise that MAX above this write's
    /// seq, making the quorum wait target the wrong (higher) seq and roll back a
    /// write that itself reached quorum. Looked up by the unique event_id, this
    /// is race-free and, for an idempotent retry, returns the ORIGINAL event's
    /// seq.
    pub fn mutation_event_seq_for_event_id(
        &self,
        event_id: &str,
    ) -> Result<Option<u64>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let seq: Option<Option<i64>> = transaction
            .query_row(
                "SELECT event_seq FROM budget_mutation_events WHERE event_id = ?1",
                rusqlite::params![event_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?;
        transaction.rollback()?;
        seq.flatten()
            .map(|value| {
                u64::try_from(value).map_err(|_| {
                    BudgetStoreError::Invariant(
                        "budget mutation event has a negative event sequence".to_string(),
                    )
                })
            })
            .transpose()
    }

    pub fn mutation_event_for_event_id(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let event = Self::load_projected_mutation_event(&transaction, event_id)?;
        transaction.rollback()?;
        Ok(event)
    }

    pub fn usage_projection_for_event_id(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let event = Self::load_mutation_event(&transaction, event_id)?;
        let Some(event) = event else {
            transaction.rollback()?;
            return Ok(None);
        };
        let Some(usage_seq) = event.usage_seq else {
            transaction.rollback()?;
            return Ok(None);
        };
        if usage_seq == 0 || usage_seq > event.event_seq {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event `{event_id}` has an invalid usage sequence {usage_seq}"
            )));
        }
        let usage = transaction
            .query_row(
                r#"
                SELECT recorded_at, invocation_count_after,
                       total_cost_exposed_after, total_cost_realized_spend_after
                FROM budget_mutation_events
                WHERE capability_id = ?1 AND grant_index = ?2
                  AND event_seq = ?3 AND usage_seq = event_seq
                "#,
                params![
                    &event.capability_id,
                    i64::from(event.grant_index),
                    budget_u64_to_sqlite(usage_seq, "usage_seq")?,
                ],
                |row| {
                    Ok(BudgetUsageRecord {
                        capability_id: event.capability_id.clone(),
                        grant_index: event.grant_index,
                        invocation_count: budget_u32_from_row(row, 1, "invocation_count_after")?,
                        updated_at: row.get(0)?,
                        seq: usage_seq,
                        total_cost_exposed: budget_u64_from_row(
                            row,
                            2,
                            "total_cost_exposed_after",
                        )?,
                        total_cost_realized_spend: budget_u64_from_row(
                            row,
                            3,
                            "total_cost_realized_spend_after",
                        )?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "budget event `{event_id}` references missing usage sequence {usage_seq}"
                ))
            })?;
        if usage.invocation_count != event.invocation_count_after
            || usage.total_cost_exposed != event.total_cost_exposed_after
            || usage.total_cost_realized_spend != event.total_cost_realized_spend_after
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event `{event_id}` usage projection counters changed"
            )));
        }
        transaction.rollback()?;
        Ok(Some(usage))
    }

    /// The quorum-witness identity of the mutation event stored under `event_id`:
    /// `(event_seq, authority_id, lease_epoch)`, or None when no such event exists
    /// or it predates seq assignment. The witness must target the event's STORED
    /// origin authority, not the current lease: an idempotent retry after
    /// leadership moved re-reads the already-written event, and peers advertise it
    /// under its ORIGINAL authority, so keying the wait on the current leader would
    /// look under the wrong origin and time out a write that already committed.
    /// A null-seq (legacy) row returns None so the caller
    /// falls back to the authority MAX rather than witnessing on seq 0.
    pub fn mutation_event_witness_for_event_id(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetEventWitness>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let row = transaction
            .query_row(
                "SELECT event_seq, authority_id, lease_epoch FROM budget_mutation_events WHERE event_id = ?1",
                rusqlite::params![event_id],
                |row| {
                    let seq: Option<i64> = row.get(0)?;
                    let authority_id: Option<String> = row.get(1)?;
                    let lease_epoch: Option<i64> = row.get(2)?;
                    Ok((seq, authority_id, lease_epoch))
                },
            )
            .optional()?;
        let witness = row
            .map(
                |(seq, authority_id, lease_epoch)| -> Result<_, BudgetStoreError> {
                    let Some(seq) = seq else {
                        return Ok(None);
                    };
                    let seq = u64::try_from(seq).map_err(|_| {
                        BudgetStoreError::Invariant(
                            "budget mutation witness has a negative event sequence".to_string(),
                        )
                    })?;
                    let lease_epoch = lease_epoch
                        .map(|epoch| {
                            u64::try_from(epoch).map_err(|_| {
                                BudgetStoreError::Invariant(
                                    "budget mutation witness has a negative lease epoch"
                                        .to_string(),
                                )
                            })
                        })
                        .transpose()?;
                    Ok(Some((seq, authority_id, lease_epoch)))
                },
            )
            .transpose()?
            .flatten();
        transaction.rollback()?;
        Ok(witness)
    }

    /// Record snapshot-carried abandoned event sequences.
    pub fn record_abandoned_event_seqs(&self, seqs: &[u64]) -> Result<(), BudgetStoreError> {
        self.require_standalone_mutation("abandoned event sequence import")?;
        if seqs.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        for &seq in seqs {
            if seq == 0 {
                continue;
            }
            transaction.execute(
                "INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq) VALUES (?1)",
                rusqlite::params![budget_u64_to_sqlite(seq, "seq")?],
            )?;
        }
        // Tombstone inserts only fill holes. Preserve the proven watermark and
        // any snapshot-installed per-origin heads so the next scan can advance.
        transaction.commit()?;
        Ok(())
    }

    /// Record snapshot-carried abandoned event sequences as inclusive ranges.
    pub fn record_abandoned_event_seq_ranges(
        &self,
        ranges: &[(u64, u64)],
    ) -> Result<(), BudgetStoreError> {
        self.require_standalone_mutation("abandoned event sequence range import")?;
        if ranges.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::insert_abandoned_event_seq_ranges(&transaction, ranges)?;
        // As above, adding covered slots cannot invalidate an acknowledged prefix.
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn insert_abandoned_event_seq_ranges(
        transaction: &rusqlite::Transaction<'_>,
        ranges: &[(u64, u64)],
    ) -> Result<(), BudgetStoreError> {
        let mut previous_end = 0;
        for &(start, end) in ranges {
            if start == 0 || end < start || start <= previous_end {
                return Err(BudgetStoreError::Invariant(
                    "abandoned budget sequence ranges must be positive, ordered, and non-overlapping"
                        .to_string(),
                ));
            }
            let start = budget_u64_to_sqlite(start, "range_start_seq")?;
            let end = budget_u64_to_sqlite(end, "range_end_seq")?;
            let overlaps_event: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM budget_mutation_events WHERE event_seq BETWEEN ?1 AND ?2)",
                rusqlite::params![start, end],
                |row| row.get::<_, i64>(0).map(|value| value != 0),
            )?;
            if overlaps_event {
                return Err(BudgetStoreError::Invariant(format!(
                    "abandoned budget sequence range {start}..={end} overlaps a mutation event"
                )));
            }
            transaction.execute(
                r#"
                INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq)
                WITH RECURSIVE run(s) AS (
                    SELECT ?1
                    UNION ALL
                    SELECT s + 1 FROM run WHERE s < ?2
                )
                SELECT s FROM run
                "#,
                rusqlite::params![start, end],
            )?;
            previous_end = end as u64;
        }
        Ok(())
    }
}

pub(super) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
