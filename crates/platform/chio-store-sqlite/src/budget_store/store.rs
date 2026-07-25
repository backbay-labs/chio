use super::*;

/// Budget-store schema revision. Bump on every schema-affecting change.
pub(crate) const BUDGET_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 10;
const BUDGET_INVOCATION_CAPTURE_SCHEMA_VERSION: i32 = 2;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const BUDGET_STORE_SCHEMA_KEY: &str = "budget";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// budget database rather than reject it as foreign.
const BUDGET_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["capability_grant_budgets"];

impl SqliteBudgetStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BudgetStoreError> {
        let path = path.as_ref();
        // Resolve any `file:` URI to its on-disk parent before creating it, so a
        // URI-configured store creates the real backing directory rather than a
        // bogus scheme-prefixed one.
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(&parent)?;
        }

        let mut connection = Connection::open(path)?;
        Self::initialize_connection(&mut connection, false)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            serving_owner: None,
        })
    }

    pub(crate) fn initialize_connection_offline(
        connection: &mut Connection,
    ) -> Result<(), BudgetStoreError> {
        Self::initialize_connection(connection, true)
    }

    fn initialize_connection(
        connection: &mut Connection,
        allow_provisioned: bool,
    ) -> Result<(), BudgetStoreError> {
        if !allow_provisioned {
            if let Some(epoch) = crate::serving_owner::provisioned_owner_epoch(connection)? {
                return Err(BudgetStoreError::Fenced {
                    expected_epoch: 0,
                    actual_epoch: Some(epoch),
                });
            }
        }
        let on_disk_schema_version = crate::check_schema_version(
            connection,
            BUDGET_STORE_SCHEMA_KEY,
            BUDGET_STORE_SUPPORTED_SCHEMA_VERSION,
            BUDGET_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;

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
                invocation_captured INTEGER NOT NULL DEFAULT 0,
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

            CREATE TABLE IF NOT EXISTS budget_import_floors (
                authority_id TEXT PRIMARY KEY,
                floor_seq    INTEGER NOT NULL DEFAULT 0,
                CHECK (floor_seq >= 0)
            );

            CREATE TABLE IF NOT EXISTS budget_ack_head_watermark (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                head_seq  INTEGER NOT NULL DEFAULT 0,
                CHECK (head_seq >= 0)
            );

            -- Incrementally-maintained per-origin ack head, so the status path does
            -- not GROUP BY the full mutation history every call. Each entry is the
            -- highest event_seq that origin has WITHIN the verified global contiguous
            -- prefix (<= the watermark); a DELETE clears it (see the trigger) so a
            -- hole forces a rebuild rather than leaving a stale-high per-origin head.
            CREATE TABLE IF NOT EXISTS budget_origin_ack_heads (
                authority_id TEXT PRIMARY KEY,
                head_seq     INTEGER NOT NULL,
                CHECK (head_seq >= 0)
            );

            -- Metadata tombstones for event_seqs that were CONSUMED but have no
            -- surviving mutation event: the leader-local rollback-retry path
            -- (existing_event_allowed) and the delta-import replace path delete a
            -- rolled-back authorize and re-append it under a fresh higher seq,
            -- permanently abandoning the original seq. Recording the abandoned seq
            -- lets the global contiguous ack head treat it as FILLED so it does not
            -- stall cluster-wide at the hole. This never over-counts: an abandoned
            -- seq is never a live write (its write was rolled back / superseded), so
            -- no witness targets it; a genuinely MISSING event (never received, never
            -- deleted here) is not recorded and still caps the head.
            CREATE TABLE IF NOT EXISTS budget_abandoned_event_seqs (
                seq INTEGER PRIMARY KEY,
                CHECK (seq > 0)
            );
            "#,
        )?;
        ensure_budget_ack_head_reset_trigger(connection)?;
        connection.execute(
            r#"
            INSERT INTO budget_replication_meta (singleton, next_seq)
            VALUES (1, 0)
            ON CONFLICT(singleton) DO NOTHING
            "#,
            [],
        )?;
        connection.execute(
            r#"
            INSERT INTO budget_ack_head_watermark (singleton, head_seq)
            VALUES (1, 0)
            ON CONFLICT(singleton) DO NOTHING
            "#,
            [],
        )?;
        ensure_budget_seq_column(connection)?;
        ensure_split_budget_cost_columns(connection)?;
        ensure_budget_hold_authority_columns(connection)?;
        ensure_budget_hold_reserved_until_column(connection)?;
        ensure_budget_hold_reserved_currency_column(connection)?;
        ensure_budget_hold_reserved_payment_reference_column(connection)?;
        ensure_budget_hold_reserved_envelope_columns(connection)?;
        ensure_budget_mutation_event_authority_columns(connection)?;
        ensure_budget_mutation_event_seq_column(connection)?;
        initialize_budget_replication_seq(connection)?;
        let migration = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let capture_column_added = ensure_budget_hold_invocation_captured_column(&migration)?;
        if on_disk_schema_version >= BUDGET_STORE_SUPPORTED_SCHEMA_VERSION && capture_column_added {
            migration.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "budget schema version declares invocation capture support but the column is missing"
                    .to_string(),
            ));
        }
        if on_disk_schema_version < BUDGET_INVOCATION_CAPTURE_SCHEMA_VERSION {
            migration.execute(
                r#"
                UPDATE budget_authorization_holds
                SET invocation_captured = 1
                WHERE disposition = 'open'
                "#,
                [],
            )?;
        }
        ensure_composite_budget_schema(&migration, on_disk_schema_version)?;
        crate::stamp_schema_version(
            &migration,
            BUDGET_STORE_SCHEMA_KEY,
            BUDGET_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        migration.commit()?;
        verify_budget_foreign_keys(connection)?;
        verify_budget_projection_invariants(connection)?;
        Self::rebuild_snapshot_proof_caches(connection)?;

        Ok(())
    }

    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<crate::serving_owner::SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner: Some(serving_owner),
        }
    }

    pub(super) fn connection(&self) -> Result<MutexGuard<'_, Connection>, BudgetStoreError> {
        self.connection.lock().map_err(|_| {
            BudgetStoreError::Invariant("sqlite budget store lock poisoned".to_string())
        })
    }

    pub(super) fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<rusqlite::Transaction<'a>, BudgetStoreError> {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::serving_owner::verify_budget_fence(&transaction, self.serving_owner.as_deref())?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .verify_authority_anchor(&transaction)
                .map_err(map_serving_owner_error)?;
        }
        Ok(transaction)
    }

    pub(super) fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<rusqlite::Transaction<'a>, BudgetStoreError> {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        crate::serving_owner::verify_budget_fence(&transaction, self.serving_owner.as_deref())?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .verify_authority_anchor(&transaction)
                .map_err(map_serving_owner_error)?;
        }
        Ok(transaction)
    }

    pub(super) fn append_joint_commit(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        kind: BudgetMutationKind,
        event_id: &str,
        event_seq: u64,
    ) -> Result<(), BudgetStoreError> {
        let owner = self.serving_owner.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "structured sqlite mutation requires a joint serving owner".to_string(),
            )
        })?;
        owner
            .append_global_commit(transaction, kind.as_str(), "budget", event_id, event_seq)
            .map_err(map_serving_owner_error)
    }

    pub(super) fn sync_joint_anchor(
        &self,
        connection: &Connection,
    ) -> Result<(), BudgetStoreError> {
        let owner = self.serving_owner.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "structured sqlite mutation requires a joint serving owner".to_string(),
            )
        })?;
        owner
            .sync_authority_anchor(connection)
            .map_err(map_serving_owner_error)
    }

    pub(super) fn commit_joint_transaction(
        &self,
        transaction: rusqlite::Transaction<'_>,
    ) -> Result<(), BudgetStoreError> {
        transaction.commit().map_err(|error| {
            let detail = format!("sqlite budget commit outcome is unknown: {error}");
            match self.serving_owner.as_ref() {
                Some(owner) => map_serving_owner_error(owner.outcome_unknown(detail)),
                None => BudgetStoreError::OutcomeUnknown(detail),
            }
        })
    }

    /// Per-origin contiguous ack head, anchored on the peer's GLOBAL contiguous
    /// import head.
    ///
    /// `event_seq` is a single store-wide dense sequence, so each origin's events
    /// are a sparse subsequence of one global stream; a per-origin gaps-and-
    /// islands run (partitioned by authority) mis-models this: an origin whose
    /// block starts mid-sequence after a leadership change looks like a gap and is
    /// wrongly dropped, stalling its writes.
    ///
    /// Instead this first computes the GLOBAL contiguous head H (the largest seq
    /// such that every global event_seq in `1..=H` is present with no hole) as a
    /// single gaps-and-islands run over the whole stream (NOT partitioned),
    /// anchored at genesis (island 0). A hole caps H below it. Legacy
    /// NULL-authority events still occupy their global slot, so they count for
    /// contiguity (a present slot is not a gap) but are never reported as an ack.
    /// It then reports, per origin, `MAX(event_seq)` among that origin's events
    /// with `event_seq <= H`.
    ///
    /// Sound because global-contiguity enforcement on the puller means holding H
    /// implies holding EVERY event (all origins) at
    /// seq `<= H`, so `head[origin] >= write.event_seq` iff the peer durably holds
    /// that write and all its predecessors. Fail-closed: a global hole caps H, so
    /// no origin is ever reported past a missing global predecessor, and a missing
    /// prefix (nothing at seq 1) yields H = 0 and no acks.
    ///
    /// NOTE: genesis anchoring assumes budget mutation events are never
    /// bulk-compacted below seq 1 (they are not today); if such compaction is
    /// added, anchor at a durable global floor instead.
    ///
    /// NOTE: a rollback-retry that abandons a seq (existing_event_allowed)
    /// leaves a permanent interior hole that caps this GLOBAL head, stalling
    /// quorum budget-writes above the hole for EVERY origin cluster-wide (not
    /// per-origin) until operator intervention - it does not self-heal, since a
    /// snapshot from the holed leader carries the hole. Fail-closed (a hole
    /// withholds quorum and never over-counts).
    /// PERF: this runs on every cluster status request (once per sync round, an
    /// interval clamped as low as 50ms), so it must not rescan the whole ledger.
    /// The GLOBAL contiguous head is maintained incrementally against a durable
    /// watermark W (`budget_ack_head_watermark`): each call only advances W over
    /// the rows ABOVE it (a window scan bounded to `event_seq > W`), so steady
    /// state cost is O(new rows), not O(history). Soundness holds because W only
    /// advances while the run stays gap-free, and any DELETE of a mutation event
    /// resets W to 0 (`reset_budget_ack_head_watermark`, backstopped structurally
    /// by the `budget_mutation_events_reset_ack_head_watermark` AFTER DELETE
    /// trigger so a future or out-of-band delete site cannot skip the reset),
    /// forcing the next call to re-verify from genesis so a hole punched below W
    /// can never leave a stale-high head that over-counts.
    pub fn budget_ack_heads(&self) -> Result<Vec<(String, u64)>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        transaction.execute(
            r#"
            UPDATE budget_ack_head_watermark
            SET head_seq = MAX(
                head_seq,
                (SELECT covered_head FROM budget_snapshot_coverage WHERE singleton = 1)
            )
            WHERE singleton = 1
            "#,
            [],
        )?;
        let watermark: i64 = transaction.query_row(
            "SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let watermark = watermark.max(0) as u64;
        let watermark_sqlite = budget_u64_to_sqlite(watermark, "head_seq")?;
        // Advance the head over slots ABOVE the watermark only. A slot is FILLED if
        // a real mutation event occupies it OR it is a recorded abandoned/tombstoned
        // seq (a rolled-back-then-re-appended write's original seq). The contiguous
        // run from W+1 has island == W (its first slot W+1 has ROW_NUMBER 1), so the
        // new head is MAX(seq) in that island, or W when W+1 is neither present nor
        // abandoned. Treating abandoned seqs as filled lets the head advance past a
        // rollback-retry hole; a genuinely MISSING event (never recorded as
        // abandoned) is NOT filled and still caps the head.
        // NULL-authority events still occupy a slot for contiguity but are never
        // reported as an ack below.
        // Fast path (avoid rescanning the ledger after a gap):
        // the contiguous run can only advance when the very next slot (W+1) is
        // FILLED (a mutation event or a recorded abandoned seq). When a real hole
        // sits at W+1 (data loss, or a legacy snapshot that lacks abandoned slots),
        // the head is pinned at W forever, yet the window query below still computes
        // ROW_NUMBER() over the whole suffix `> W` on every status-path call. Probe
        // the single W+1 slot first (an indexed point lookup): if it is absent, the
        // head is W, so skip the O(suffix) window scan entirely. This is purely an
        // optimization: the window query ALSO yields exactly W when W+1 is absent
        // (the smallest filled seq > W then has island >= W+1, so no row matches the
        // island == W run and COALESCE(MAX(seq), W) collapses to W), so the
        // genesis-anchored gaps-and-islands head is unchanged.
        let next_slot = watermark_sqlite.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("budget acknowledgement head overflowed i64".to_string())
        })?;
        let next_slot_filled: bool = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_mutation_events WHERE event_seq = ?1
                UNION ALL
                SELECT 1 FROM budget_abandoned_event_seqs WHERE seq = ?1
            )
            "#,
            rusqlite::params![next_slot],
            |row| row.get::<_, i64>(0).map(|value| value != 0),
        )?;
        let head: i64 = if next_slot_filled {
            transaction.query_row(
                r#"
                WITH filled AS (
                    SELECT event_seq AS seq
                    FROM budget_mutation_events
                    WHERE event_seq IS NOT NULL AND event_seq > ?1
                    UNION
                    SELECT seq
                    FROM budget_abandoned_event_seqs
                    WHERE seq > ?1
                ),
                run AS (
                    SELECT
                        seq,
                        seq - ROW_NUMBER() OVER (ORDER BY seq) AS island
                    FROM filled
                )
                SELECT COALESCE(MAX(seq), ?1) AS head_seq
                FROM run
                WHERE island = ?1
                "#,
                rusqlite::params![watermark_sqlite],
                |row| row.get(0),
            )?
        } else {
            watermark_sqlite
        };
        let head = head.max(0) as u64;
        if head > watermark {
            let head_sqlite = budget_u64_to_sqlite(head, "head_seq")?;
            transaction.execute(
                "UPDATE budget_ack_head_watermark SET head_seq = ?1 WHERE singleton = 1",
                rusqlite::params![head_sqlite],
            )?;
            // Fold ONLY the newly-covered rows (watermark, head] into the durable
            // per-origin heads, so the status path never GROUPs the full history:
            // steady-state cost is O(new rows). MAX keeps each origin monotone
            // within a hole-free window; a DELETE clears this table (trigger +
            // reset helper), so a per-origin head can never sit above a hole.
            transaction.execute(
                r#"
                INSERT INTO budget_origin_ack_heads (authority_id, head_seq)
                SELECT authority_id, MAX(event_seq)
                FROM budget_mutation_events
                WHERE authority_id IS NOT NULL
                  AND event_seq IS NOT NULL
                  AND event_seq > ?1
                  AND event_seq <= ?2
                GROUP BY authority_id
                ON CONFLICT(authority_id)
                    DO UPDATE SET head_seq = MAX(head_seq, excluded.head_seq)
                "#,
                rusqlite::params![watermark_sqlite, head_sqlite],
            )?;
        }
        let mut statement =
            transaction.prepare("SELECT authority_id, head_seq FROM budget_origin_ack_heads")?;
        let rows = statement
            .query_map([], |row| {
                let origin: String = row.get(0)?;
                let ack_head = budget_u64_from_row(row, 1, "ack_head")?;
                Ok((origin, ack_head))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(BudgetStoreError::from)?;
        drop(statement);
        transaction.commit()?;
        Ok(rows)
    }

    /// Reset the durable contiguous ack-head watermark to 0, forcing the next
    /// `budget_ack_heads` call to re-verify the global run from genesis. Called
    /// whenever a mutation event is DELETED (a hole may have been punched at or
    /// below the watermark): re-verification caps the head below the hole so a
    /// stale-high watermark can never over-count a witness.
    ///
    /// This is redundant with the `budget_mutation_events_reset_ack_head_watermark`
    /// AFTER DELETE trigger created in `open` (defense-in-depth): the trigger fires
    /// structurally on every delete against the table, so this manual call is a
    /// belt-and-suspenders in-transaction reset at each known call site, not the
    /// sole enforcement point.
    #[cfg(test)]
    pub(crate) fn reset_budget_ack_head_watermark(
        transaction: &rusqlite::Transaction<'_>,
    ) -> Result<(), BudgetStoreError> {
        transaction.execute(
            "UPDATE budget_ack_head_watermark SET head_seq = 0 WHERE singleton = 1",
            [],
        )?;
        // Clear the incrementally-maintained per-origin heads too: a hole below a
        // per-origin head would otherwise leave it stale-high until a full rebuild.
        transaction.execute("DELETE FROM budget_origin_ack_heads", [])?;
        Ok(())
    }

    /// The abandoned/tombstoned event_seqs (rolled-back-then-re-appended writes'
    /// original seqs) that `budget_ack_heads` treats as filled slots. Replicated
    /// in the cluster snapshot so a FRESH follower - which never held the original
    /// event and so never fired the delete-trigger that records it locally - still
    /// learns the slot is abandoned and does not stall its contiguous head at the
    /// hole.
    pub fn list_abandoned_event_seqs(&self) -> Result<Vec<u64>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement =
            transaction.prepare("SELECT seq FROM budget_abandoned_event_seqs ORDER BY seq ASC")?;
        let rows = statement.query_map([], |row| {
            let seq: i64 = row.get(0)?;
            Ok(seq.max(0) as u64)
        })?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        transaction.rollback()?;
        Ok(rows)
    }

    /// The abandoned event_seqs RANGE-ENCODED as inclusive `(start, end)` runs of
    /// consecutive seqs (ascending, non-overlapping).
    ///
    /// The cluster snapshot carries the abandoned set this way instead of one entry
    /// per seq. A rollback storm abandons a long CONTIGUOUS run of seqs; enumerated,
    /// that is millions of integers that push the snapshot body past
    /// MAX_PEER_RESPONSE_BYTES, so the force-snapshot recovery path fails to decode
    /// cluster_snapshot() and the peer stalls in force_snapshot forever (unlike the
    /// delta path, the snapshot backstop has no further fallback). Range-encoded,
    /// each contiguous run collapses to one
    /// small pair, and the run count is bounded by the number of live mutation events
    /// (a run is separated from the next by a filled non-abandoned slot), which the
    /// snapshot already carries and which dominate the byte budget - so if the events
    /// fit under the cap the ranges do too. The encoding is LOSSLESS: a follower
    /// expands the runs to the identical seq set, so the filled-or-abandoned
    /// head-advance semantics are preserved bit-for-bit. Computed in SQL
    /// (gaps-and-islands) so the full seq set is never materialized here either.
    pub fn list_abandoned_event_seq_ranges(&self) -> Result<Vec<(u64, u64)>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
            r#"
            SELECT MIN(seq) AS start_seq, MAX(seq) AS end_seq
            FROM (
                SELECT seq, seq - ROW_NUMBER() OVER (ORDER BY seq) AS island
                FROM budget_abandoned_event_seqs
            )
            GROUP BY island
            ORDER BY start_seq ASC
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            let start: i64 = row.get(0)?;
            let end: i64 = row.get(1)?;
            Ok((start.max(0) as u64, end.max(0) as u64))
        })?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        transaction.rollback()?;
        Ok(rows)
    }

    /// Abandoned event_seqs strictly above `after_seq` (ascending). The budget
    /// delta endpoint returns these alongside the pulled events so the puller can
    /// treat the abandoned slots as filled and not reject the leader's legitimately
    /// gappy stream.
    pub fn list_abandoned_event_seqs_after(
        &self,
        after_seq: u64,
    ) -> Result<Vec<u64>, BudgetStoreError> {
        let after_seq = budget_u64_to_sqlite(after_seq, "after_seq")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
            "SELECT seq FROM budget_abandoned_event_seqs WHERE seq > ?1 ORDER BY seq ASC",
        )?;
        let rows = statement.query_map(rusqlite::params![after_seq], |row| {
            let seq: i64 = row.get(0)?;
            Ok(seq.max(0) as u64)
        })?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        transaction.rollback()?;
        Ok(rows)
    }

    /// Abandoned event_seqs in `(after_seq, up_to_seq]` (ascending), at most
    /// `limit` entries.
    ///
    /// The budget delta endpoint uses this to BOUND the abandoned list it serves.
    /// A rollback storm can pack an
    /// arbitrarily large abandoned window between the follower cursor and the next
    /// live event; serializing all of it (the old unbounded
    /// `list_abandoned_event_seqs_after` + in-memory `<= page_max` filter) could
    /// exceed the peer-response byte cap, so the client rejects the body while
    /// decoding and never gets to classify the oversized window as
    /// snapshot-recovery, pinning the cursor forever. Both the upper bound and the
    /// row cap are pushed into SQL so a huge window is never materialized here.
    pub fn list_abandoned_event_seqs_in_range(
        &self,
        after_seq: u64,
        up_to_seq: u64,
        limit: usize,
    ) -> Result<Vec<u64>, BudgetStoreError> {
        let after_seq = budget_u64_to_sqlite(after_seq, "after_seq")?;
        let up_to_seq = budget_u64_to_sqlite(up_to_seq, "up_to_seq")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
            "SELECT seq FROM budget_abandoned_event_seqs \
             WHERE seq > ?1 AND seq <= ?2 ORDER BY seq ASC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            rusqlite::params![after_seq, up_to_seq, limit as i64],
            |row| {
                let seq: i64 = row.get(0)?;
                Ok(seq.max(0) as u64)
            },
        )?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        transaction.rollback()?;
        Ok(rows)
    }

    pub(super) fn upsert_usage_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetUsageRecord,
    ) -> Result<(), BudgetStoreError> {
        let existing = transaction
            .query_row(
                r#"
                SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                       total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![&record.capability_id, i64::from(record.grant_index)],
                record_from_row,
            )
            .optional()?;
        if let Some(existing) = existing
            .as_ref()
            .filter(|existing| existing.seq == record.seq)
        {
            if existing != record {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget usage `{}` grant {} reused sequence {} with different counters",
                    record.capability_id, record.grant_index, record.seq
                )));
            }
            return Ok(());
        }
        let seq = budget_u64_to_sqlite(record.seq, "seq")?;
        let total_cost_exposed =
            budget_u64_to_sqlite(record.total_cost_exposed, "total_cost_exposed")?;
        let total_cost_realized_spend = budget_u64_to_sqlite(
            record.total_cost_realized_spend,
            "total_cost_realized_spend",
        )?;
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
                    WHEN excluded.seq > capability_grant_budgets.seq
                        THEN excluded.invocation_count
                    ELSE capability_grant_budgets.invocation_count
                END,
                updated_at = CASE
                    WHEN excluded.seq > capability_grant_budgets.seq
                        THEN excluded.updated_at
                    ELSE capability_grant_budgets.updated_at
                END,
                total_cost_exposed = CASE
                    WHEN excluded.seq > capability_grant_budgets.seq
                        THEN excluded.total_cost_exposed
                    ELSE capability_grant_budgets.total_cost_exposed
                END,
                total_cost_realized_spend = CASE
                    WHEN excluded.seq > capability_grant_budgets.seq
                        THEN excluded.total_cost_realized_spend
                    ELSE capability_grant_budgets.total_cost_realized_spend
                END,
                seq = MAX(capability_grant_budgets.seq, excluded.seq)
            "#,
            params![
                &record.capability_id,
                i64::from(record.grant_index),
                i64::from(record.invocation_count),
                record.updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend,
            ],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn delete_mutation_event(&self, event_id: &str) -> Result<(), BudgetStoreError> {
        self.require_standalone_mutation("budget mutation event deletion")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        transaction.execute(
            "DELETE FROM budget_mutation_events WHERE event_id = ?1",
            params![event_id],
        )?;
        Self::reset_budget_ack_head_watermark(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn hold_authority(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let authority = Self::load_hold(&transaction, hold_id)?.and_then(|hold| hold.authority);
        transaction.rollback()?;
        Ok(authority)
    }

    pub fn import_mutation_record(
        &self,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        self.require_standalone_mutation("budget mutation record import")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::import_mutation_record_in_transaction(&transaction, record)?;
        Self::reconcile_imported_usages(&transaction, &[], std::slice::from_ref(record))?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn import_mutation_record_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        Self::validate_import_record_sqlite_range(record)?;
        let mut normalized = record.clone();
        if legacy_event_lifecycle_is_unset(&normalized) {
            let lifecycle = imported_event_lifecycle(transaction, &normalized)?;
            normalized.authorization_outcome = lifecycle.0;
            normalized.invocation_state_before = lifecycle.1;
            normalized.invocation_state_after = lifecycle.2;
            normalized.monetary_state_before = lifecycle.3;
            normalized.monetary_state_after = lifecycle.4;
        }
        Self::validate_supported_import_record(&normalized)?;
        let record = &normalized;
        if let Some(hold_id) = record.hold_id.as_deref() {
            Self::reject_structured_hold_from_legacy_writer(
                transaction,
                Some(hold_id),
                "budget mutation import",
            )?;
        }

        let duplicate_event =
            if let Some(existing) = Self::load_mutation_event(transaction, &record.event_id)? {
                if Self::same_imported_mutation(&existing, record) {
                    true
                } else {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget event_id `{}` was reused for a different mutation",
                        record.event_id
                    )));
                }
            } else {
                Self::validate_import_hold_frontier(transaction, record)?;
                Self::validate_import_event_usage_chain(transaction, record)?;
                Self::insert_imported_mutation_event(transaction, record)?;
                false
            };
        if duplicate_event {
            return Ok(());
        }

        raise_budget_replication_seq_floor(transaction, record.event_seq)?;
        if let Some(usage_seq) = record.usage_seq {
            raise_budget_replication_seq_floor(transaction, usage_seq)?;
        }
        Self::apply_imported_hold_state(transaction, record)?;
        Ok(())
    }

    fn validate_supported_import_record(
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        let unsupported_kind = matches!(
            record.kind,
            BudgetMutationKind::ReserveInvocation
                | BudgetMutationKind::AuthorizeCumulativeApproval
                | BudgetMutationKind::ReverseInvocation
                | BudgetMutationKind::CaptureSpend
        );
        let composite_projection = record.admission_binding.is_some()
            || !record.invocation_quota_usages.is_empty()
            || !record.invocation_quota_mutations.is_empty()
            || record.cumulative_approval.is_some()
            || record.cumulative_approval_mutation.is_some()
            || record.cumulative_approval_set_digest.is_some();
        if unsupported_kind || composite_projection {
            return Err(BudgetStoreError::Invariant(format!(
                "budget mutation `{}` uses state unsupported by the sqlite budget store",
                record.kind.as_str()
            )));
        }
        validate_legacy_event_lifecycle(record)?;
        Self::validate_import_event_shape(record)?;
        Ok(())
    }

    fn validate_import_record_sqlite_range(
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
        if record.event_seq == 0 || record.usage_seq == Some(0) {
            return Err(BudgetStoreError::Invariant(
                "imported budget sequences must be positive".to_string(),
            ));
        }
        if record
            .usage_seq
            .is_some_and(|usage_seq| usage_seq > record.event_seq)
        {
            return Err(BudgetStoreError::Invariant(
                "imported budget usage sequence exceeds its event sequence".to_string(),
            ));
        }
        budget_u64_to_sqlite(record.event_seq, "event_seq")?;
        optional_budget_u64_to_sqlite(record.usage_seq, "usage_seq")?;
        budget_u64_to_sqlite(record.exposure_units, "exposure_units")?;
        budget_u64_to_sqlite(record.realized_spend_units, "realized_spend_units")?;
        optional_budget_u64_to_sqlite(
            record.max_cost_per_invocation,
            "max_exposure_per_invocation",
        )?;
        optional_budget_u64_to_sqlite(record.max_total_cost_units, "max_total_exposure_units")?;
        budget_u64_to_sqlite(record.total_cost_exposed_after, "total_cost_exposed_after")?;
        budget_u64_to_sqlite(
            record.total_cost_realized_spend_after,
            "total_cost_realized_spend_after",
        )?;
        if let Some(authority) = record.authority.as_ref() {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        Ok(())
    }

    /// Insert one imported mutation event row verbatim. Shared by the new-event
    /// import path and the follower rollback-retry REPLACE path (which deletes the
    /// superseded row and tombstones its seq before re-inserting the leader's
    /// re-appended event under its fresh higher event_seq). A plain INSERT is
    /// deliberate and fail-closed: the unique event_seq index rejects a corrupt
    /// stream that reused a seq for a different event rather than silently masking
    /// it.
    fn insert_imported_mutation_event(
        transaction: &rusqlite::Transaction<'_>,
        record: &BudgetMutationRecord,
    ) -> Result<(), BudgetStoreError> {
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
                    lease_epoch,
                    authorization_outcome,
                    invocation_state_before,
                    invocation_state_after,
                    monetary_state_before,
                    monetary_state_after
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                    ?21, ?22, ?23, ?24, ?25
                )
                "#,
            params![
                record.event_id,
                record.hold_id,
                record.capability_id,
                i64::from(record.grant_index),
                record.kind.as_str(),
                record
                    .allowed
                    .map(|value| if value { 1_i64 } else { 0_i64 }),
                record.recorded_at,
                budget_u64_to_sqlite(record.event_seq, "event_seq")?,
                optional_budget_u64_to_sqlite(record.usage_seq, "usage_seq")?,
                budget_u64_to_sqlite(record.exposure_units, "exposure_units")?,
                budget_u64_to_sqlite(record.realized_spend_units, "realized_spend_units")?,
                record.max_invocations.map(i64::from),
                optional_budget_u64_to_sqlite(
                    record.max_cost_per_invocation,
                    "max_exposure_per_invocation",
                )?,
                optional_budget_u64_to_sqlite(
                    record.max_total_cost_units,
                    "max_total_exposure_units",
                )?,
                i64::from(record.invocation_count_after),
                budget_u64_to_sqlite(record.total_cost_exposed_after, "total_cost_exposed_after",)?,
                budget_u64_to_sqlite(
                    record.total_cost_realized_spend_after,
                    "total_cost_realized_spend_after",
                )?,
                record
                    .authority
                    .as_ref()
                    .map(|value| value.authority_id.as_str()),
                record
                    .authority
                    .as_ref()
                    .map(|value| value.lease_id.as_str()),
                record
                    .authority
                    .as_ref()
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                record
                    .authorization_outcome
                    .map(budget_authorization_outcome_text),
                budget_invocation_state_text(record.invocation_state_before),
                budget_invocation_state_text(record.invocation_state_after),
                budget_monetary_state_text(record.monetary_state_before),
                budget_monetary_state_text(record.monetary_state_after),
            ],
        )?;
        Ok(())
    }

    fn same_imported_mutation(
        existing: &BudgetMutationRecord,
        imported: &BudgetMutationRecord,
    ) -> bool {
        existing.event_id == imported.event_id
            && existing.event_seq == imported.event_seq
            && existing.usage_seq == imported.usage_seq
            && existing.recorded_at == imported.recorded_at
            && existing.hold_id == imported.hold_id
            && existing.capability_id == imported.capability_id
            && existing.grant_index == imported.grant_index
            && existing.kind == imported.kind
            && existing.allowed == imported.allowed
            && existing.authorization_outcome == imported.authorization_outcome
            && existing.invocation_state_before == imported.invocation_state_before
            && existing.invocation_state_after == imported.invocation_state_after
            && existing.monetary_state_before == imported.monetary_state_before
            && existing.monetary_state_after == imported.monetary_state_after
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
        let after_seq = optional_budget_u64_to_sqlite(after_seq, "after_seq")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
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
        let rows = statement.query_map(params![after_seq, limit as i64], record_from_row)?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        transaction.rollback()?;
        Ok(rows)
    }

    pub fn list_all_usages(&self) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
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
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        transaction.rollback()?;
        Ok(rows)
    }

    pub fn list_mutation_events_after_seq(
        &self,
        limit: usize,
        after_event_seq: u64,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let after_event_seq = budget_u64_to_sqlite(after_event_seq, "after_event_seq")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
            r#"
            SELECT event_id
            FROM budget_mutation_events
            WHERE event_seq > ?1
            ORDER BY event_seq ASC
            LIMIT ?2
            "#,
        )?;
        let event_ids = statement
            .query_map(params![after_event_seq, limit as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let events = event_ids
            .iter()
            .map(|event_id| {
                Self::load_projected_mutation_event(&transaction, event_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "budget mutation event `{event_id}` disappeared while listing"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        transaction.rollback()?;
        Ok(events)
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
                    invocation_captured,
                    disposition,
                    authority_id,
                    lease_id,
                    lease_epoch
                FROM budget_authorization_holds
                WHERE hold_id = ?1
                "#,
                params![hold_id],
                |row| {
                    let disposition = row.get::<_, String>(7)?;
                    let authority =
                        sqlite_budget_event_authority(row.get(8)?, row.get(9)?, row.get(10)?)?;
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
                        invocation_captured: row.get::<_, i64>(6)? > 0,
                        disposition: HoldDisposition::parse(&disposition).ok_or_else(|| {
                            rusqlite::Error::FromSqlConversionFailure(
                                7,
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

    pub(super) fn has_captured_hold(
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<bool, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM budget_authorization_holds
                    WHERE capability_id = ?1
                      AND grant_index = ?2
                      AND invocation_captured = 1
                )
                "#,
                params![capability_id, grant_index as i64],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub(super) fn has_live_hold(
        transaction: &rusqlite::Transaction<'_>,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<bool, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM budget_authorization_holds
                    WHERE capability_id = ?1
                      AND grant_index = ?2
                      AND invocation_count_debited = 1
                      AND disposition != 'reversed'
                )
                "#,
                params![capability_id, grant_index as i64],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub(super) fn load_mutation_event(
        connection: &Connection,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        connection
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
                    lease_epoch,
                    authorization_outcome,
                    invocation_state_before,
                    invocation_state_after,
                    monetary_state_before,
                    monetary_state_after
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
                invocation_captured,
                disposition,
                authority_id,
                lease_id,
                lease_epoch,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, ?6, ?7, ?8, ?9, ?10, ?10)
            "#,
            params![
                hold_id,
                capability_id,
                grant_index as i64,
                budget_u64_to_sqlite(authorized_exposure_units, "authorized_exposure_units",)?,
                budget_u64_to_sqlite(authorized_exposure_units, "remaining_exposure_units",)?,
                HoldDisposition::Open.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
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
                budget_u64_to_sqlite(remaining_exposure_units, "remaining_exposure_units",)?,
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
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
        invocation_captured: bool,
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
                invocation_captured,
                disposition,
                authority_id,
                lease_id,
                lease_epoch,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, ?10, ?11, ?11)
            ON CONFLICT(hold_id) DO UPDATE SET
                capability_id = excluded.capability_id,
                grant_index = excluded.grant_index,
                authorized_exposure_units = excluded.authorized_exposure_units,
                remaining_exposure_units = excluded.remaining_exposure_units,
                invocation_count_debited = excluded.invocation_count_debited,
                invocation_captured = excluded.invocation_captured,
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
                budget_u64_to_sqlite(authorized_exposure_units, "authorized_exposure_units",)?,
                budget_u64_to_sqlite(remaining_exposure_units, "remaining_exposure_units",)?,
                if invocation_captured { 1_i64 } else { 0_i64 },
                disposition.as_str(),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
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

    pub(super) fn validate_replay_authority(
        event_id: &str,
        persisted: Option<&BudgetEventAuthority>,
        requested: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        if persisted == requested {
            return Ok(());
        }
        Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{event_id}` authority metadata does not match the original mutation"
        )))
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn existing_event_allowed(
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
                    max_total_exposure_units
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
        let existing_record =
            Self::load_mutation_event(transaction, event_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "budget mutation event disappeared during idempotency check".to_string(),
                )
            })?;
        if !mutation_matches {
            return Err(BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` was reused for a different mutation"
            )));
        }
        Self::validate_replay_authority(event_id, existing_record.authority.as_ref(), authority)?;
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
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        validate_budget_grant_index(grant_index)?;
        let event_id = match event_id {
            Some(event_id) => event_id.to_string(),
            None => Self::generated_event_id(transaction)?,
        };
        let recorded_at = unix_now();
        let (
            authorization_outcome,
            invocation_state_before,
            invocation_state_after,
            monetary_state_before,
            monetary_state_after,
        ) = appended_event_lifecycle(transaction, hold_id, kind, allowed, exposure_units)?;
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
                lease_epoch,
                authorization_outcome,
                invocation_state_before,
                invocation_state_after,
                monetary_state_before,
                monetary_state_after
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                ?21, ?22, ?23, ?24, ?25
            )
            "#,
            params![
                event_id,
                hold_id,
                capability_id,
                grant_index as i64,
                kind.as_str(),
                allowed.map(|value| if value { 1_i64 } else { 0_i64 }),
                recorded_at,
                budget_u64_to_sqlite(event_seq, "event_seq")?,
                optional_budget_u64_to_sqlite(usage_seq, "usage_seq")?,
                budget_u64_to_sqlite(exposure_units, "exposure_units")?,
                budget_u64_to_sqlite(realized_spend_units, "realized_spend_units")?,
                max_invocations.map(i64::from),
                optional_budget_u64_to_sqlite(
                    max_cost_per_invocation,
                    "max_exposure_per_invocation",
                )?,
                optional_budget_u64_to_sqlite(max_total_cost_units, "max_total_exposure_units",)?,
                i64::from(invocation_count_after),
                budget_u64_to_sqlite(total_cost_exposed_after, "total_cost_exposed_after",)?,
                budget_u64_to_sqlite(
                    total_cost_realized_spend_after,
                    "total_cost_realized_spend_after",
                )?,
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                authorization_outcome.map(budget_authorization_outcome_text),
                budget_invocation_state_text(invocation_state_before),
                budget_invocation_state_text(invocation_state_after),
                budget_monetary_state_text(monetary_state_before),
                budget_monetary_state_text(monetary_state_after),
            ],
        )?;
        if usage_seq == Some(event_seq) {
            let changed = transaction.execute(
                r#"
                UPDATE capability_grant_budgets SET updated_at = ?3
                WHERE capability_id = ?1 AND grant_index = ?2 AND seq = ?4
                "#,
                params![
                    capability_id,
                    grant_index as i64,
                    recorded_at,
                    budget_u64_to_sqlite(event_seq, "event_seq")?,
                ],
            )?;
            if changed != 1 {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event `{event_id}` has no matching usage projection"
                )));
            }
        }
        Ok(BudgetMutationRecord {
            event_id,
            hold_id: hold_id.map(ToOwned::to_owned),
            admission_binding: None,
            capability_id: capability_id.to_string(),
            grant_index: grant_index as u32,
            kind,
            allowed,
            authorization_outcome,
            invocation_state_before,
            invocation_state_after,
            monetary_state_before,
            monetary_state_after,
            recorded_at,
            event_seq,
            usage_seq,
            exposure_units,
            realized_spend_units,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
            invocation_count_after,
            invocation_quota_usages: Vec::new(),
            invocation_quota_mutations: Vec::new(),
            cumulative_approval: None,
            cumulative_approval_mutation: None,
            cumulative_approval_set_digest: None,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            authority: authority.cloned(),
        })
    }

    pub fn try_increment_with_event_id(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.require_standalone_mutation("unbound invocation increment")?;
        validate_budget_grant_index(grant_index)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_legacy_admission_after_composite_history(
            &transaction,
            capability_id,
            grant_index,
        )?;

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

        let invocation_count_after = current.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("invocation count overflowed u32".to_string())
        })?;
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
                i64::from(invocation_count_after),
                updated_at,
                budget_u64_to_sqlite(seq, "seq")?,
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
            invocation_count_after,
            total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(true)
    }
}

pub(super) fn map_serving_owner_error(
    error: crate::serving_owner::SqliteServingOwnerError,
) -> BudgetStoreError {
    match error {
        crate::serving_owner::SqliteServingOwnerError::OutcomeUnknown(detail) => {
            BudgetStoreError::OutcomeUnknown(detail)
        }
        error => BudgetStoreError::Invariant(error.to_string()),
    }
}
