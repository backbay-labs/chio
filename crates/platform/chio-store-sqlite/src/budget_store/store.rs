use super::*;

/// Quorum-witness identity of a stored budget mutation event: its `event_seq`,
/// origin `authority_id`, and origin `lease_epoch`.
pub type BudgetEventWitness = (u64, Option<String>, Option<u64>);

/// Budget-store schema revision. Bump on every schema-affecting change.
const BUDGET_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
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
        crate::check_schema_version(
            &connection,
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

            CREATE TABLE IF NOT EXISTS payment_journal (
                request_id          TEXT PRIMARY KEY,
                capability_id       TEXT NOT NULL,
                grant_index         INTEGER NOT NULL,
                hold_id             TEXT,
                rail                TEXT NOT NULL,
                authorization_id    TEXT,
                transaction_id      TEXT,
                amount_units        INTEGER NOT NULL,
                settle_action       TEXT,
                settle_amount_units INTEGER,
                currency            TEXT NOT NULL,
                state               TEXT NOT NULL,
                created_at          INTEGER NOT NULL,
                updated_at          INTEGER NOT NULL,
                tenant_id           TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_payment_journal_state
                ON payment_journal(state);

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
        ensure_budget_ack_head_reset_trigger(&connection)?;
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
        ensure_budget_seq_column(&connection)?;
        ensure_split_budget_cost_columns(&connection)?;
        ensure_budget_hold_authority_columns(&connection)?;
        ensure_budget_mutation_event_authority_columns(&connection)?;
        ensure_budget_mutation_event_seq_column(&connection)?;
        initialize_budget_replication_seq(&mut connection)?;
        crate::stamp_schema_version(
            &connection,
            BUDGET_STORE_SCHEMA_KEY,
            BUDGET_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(super) fn connection(&self) -> Result<MutexGuard<'_, Connection>, BudgetStoreError> {
        self.connection.lock().map_err(|_| {
            BudgetStoreError::Invariant("sqlite budget store lock poisoned".to_string())
        })
    }

    /// Highest budget mutation event_seq, or 0 when empty. Mirrors the private
    /// max_budget_mutation_event_seq helper (replication.rs) but is a public
    /// head read for the status path.
    pub fn max_mutation_event_seq(&self) -> Result<u64, BudgetStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(event_seq), 0) FROM budget_mutation_events",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
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
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(event_seq), 0) FROM budget_mutation_events WHERE authority_id = ?1",
            rusqlite::params![authority_id],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
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
        let connection = self.connection()?;
        let seq: Option<Option<i64>> = connection
            .query_row(
                "SELECT event_seq FROM budget_mutation_events WHERE event_id = ?1",
                rusqlite::params![event_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?;
        Ok(seq.flatten().map(|value| value.max(0) as u64))
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
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let watermark: i64 = transaction.query_row(
            "SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let watermark = watermark.max(0) as u64;
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
        let next_slot = (watermark as i64).saturating_add(1);
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
                rusqlite::params![watermark as i64],
                |row| row.get(0),
            )?
        } else {
            watermark as i64
        };
        let head = head.max(0) as u64;
        if head > watermark {
            transaction.execute(
                "UPDATE budget_ack_head_watermark SET head_seq = ?1 WHERE singleton = 1",
                rusqlite::params![head as i64],
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
                rusqlite::params![watermark as i64, head as i64],
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
    fn reset_budget_ack_head_watermark(
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
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT seq FROM budget_abandoned_event_seqs ORDER BY seq ASC")?;
        let rows = statement.query_map([], |row| {
            let seq: i64 = row.get(0)?;
            Ok(seq.max(0) as u64)
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(BudgetStoreError::from)
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
        let connection = self.connection()?;
        let mut statement = connection.prepare(
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
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(BudgetStoreError::from)
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
        let connection = self.connection()?;
        let row = connection
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
        Ok(row.and_then(|(seq, authority_id, lease_epoch)| {
            seq.map(|seq| {
                (
                    seq.max(0) as u64,
                    authority_id,
                    lease_epoch.map(|epoch| epoch.max(0) as u64),
                )
            })
        }))
    }

    /// Abandoned event_seqs strictly above `after_seq` (ascending). The budget
    /// delta endpoint returns these alongside the pulled events so the puller can
    /// treat the abandoned slots as filled and not reject the leader's legitimately
    /// gappy stream.
    pub fn list_abandoned_event_seqs_after(
        &self,
        after_seq: u64,
    ) -> Result<Vec<u64>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT seq FROM budget_abandoned_event_seqs WHERE seq > ?1 ORDER BY seq ASC",
        )?;
        let rows = statement.query_map(rusqlite::params![after_seq as i64], |row| {
            let seq: i64 = row.get(0)?;
            Ok(seq.max(0) as u64)
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(BudgetStoreError::from)
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
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT seq FROM budget_abandoned_event_seqs \
             WHERE seq > ?1 AND seq <= ?2 ORDER BY seq ASC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            rusqlite::params![after_seq as i64, up_to_seq as i64, limit as i64],
            |row| {
                let seq: i64 = row.get(0)?;
                Ok(seq.max(0) as u64)
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(BudgetStoreError::from)
    }

    /// Record snapshot-carried abandoned event_seqs (see `list_abandoned_event_seqs`).
    /// Fail-closed: this only ADDS filled slots (an abandoned seq is never a live
    /// write, so it cannot inflate any origin's ack head), and it resets the
    /// watermark so the next `budget_ack_heads` recomputes with the new slots.
    pub fn record_abandoned_event_seqs(&self, seqs: &[u64]) -> Result<(), BudgetStoreError> {
        if seqs.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for &seq in seqs {
            if seq == 0 {
                continue;
            }
            transaction.execute(
                "INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq) VALUES (?1)",
                rusqlite::params![seq as i64],
            )?;
        }
        Self::reset_budget_ack_head_watermark(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    /// Record snapshot-carried abandoned event_seqs given as inclusive `(start, end)`
    /// RANGES (see `list_abandoned_event_seq_ranges`).
    ///
    /// Each range is expanded to its individual seqs IN SQL via a recursive CTE, so a
    /// follower never materializes a huge run (a rollback-storm range covering
    /// millions of seqs) as an in-memory Vec just to insert it row by row. The stored
    /// rows are identical to `record_abandoned_event_seqs` fed the enumerated set, so
    /// the head-advance semantics are unchanged; this is purely how the WIRE avoids
    /// the per-seq blow-up.
    /// Fail-closed: an abandoned seq is never a live write, so it can only ADD filled
    /// slots, and the watermark is reset so `budget_ack_heads` recomputes.
    pub fn record_abandoned_event_seq_ranges(
        &self,
        ranges: &[(u64, u64)],
    ) -> Result<(), BudgetStoreError> {
        if ranges.is_empty() {
            return Ok(());
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut recorded_any = false;
        for &(start, end) in ranges {
            // Skip seq 0 (never a real event slot) and any malformed inverted range.
            let start = start.max(1);
            if end < start {
                continue;
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
                rusqlite::params![start as i64, end as i64],
            )?;
            recorded_any = true;
        }
        if recorded_any {
            Self::reset_budget_ack_head_watermark(&transaction)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// The durable trusted floor for one origin (0 when none recorded).
    ///
    /// IMPORTANT: this floor does NOT gate the budget ack
    /// head. `budget_ack_heads` is GENESIS-anchored: it walks the contiguous global
    /// event prefix from seq 1 (over `budget_mutation_events` UNION the recorded
    /// abandoned seqs, from a watermark that resets to 0 on any delete) and never
    /// reads `budget_import_floors`. Raising an origin's import floor therefore
    /// never advances that origin's ack head, and a delta page that jumps over the
    /// floor is still rejected as non-contiguous by the puller. The floor is written
    /// only on snapshot install (`record_budget_import_floors`) to record the
    /// provably-covered lower bound of an installed snapshot. This singular reader
    /// has NO production consumer; it is a diagnostic/test surface that verifies
    /// snapshot install persisted the floor. Do not wire it into ack-head, quorum,
    /// or witness accounting.
    pub fn budget_import_floor(&self, authority_id: &str) -> Result<u64, BudgetStoreError> {
        let connection = self.connection()?;
        let floor: i64 = connection
            .query_row(
                "SELECT floor_seq FROM budget_import_floors WHERE authority_id = ?1",
                rusqlite::params![authority_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        Ok(floor.max(0) as u64)
    }

    /// Raise each origin's trusted floor to (min covered event_seq) - 1 for the
    /// events in a freshly installed snapshot. Never lowers a floor. A
    /// puller-introduced gap can never raise the floor because the puller never
    /// calls this; only snapshot install does.
    pub fn record_budget_import_floors(
        &self,
        events: &[BudgetMutationRecord],
    ) -> Result<(), BudgetStoreError> {
        use std::collections::BTreeMap;
        let mut min_by_origin: BTreeMap<&str, u64> = BTreeMap::new();
        for event in events {
            let Some(authority) = event.authority.as_ref() else {
                continue;
            };
            let entry = min_by_origin
                .entry(authority.authority_id.as_str())
                .or_insert(event.event_seq);
            *entry = (*entry).min(event.event_seq);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (origin, min_seq) in min_by_origin {
            let floor = min_seq.saturating_sub(1);
            transaction.execute(
                "INSERT INTO budget_import_floors (authority_id, floor_seq) VALUES (?1, ?2) \
                 ON CONFLICT(authority_id) DO UPDATE SET floor_seq = MAX(floor_seq, excluded.floor_seq)",
                rusqlite::params![origin, floor as i64],
            )?;
        }
        transaction.commit()?;
        Ok(())
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
        Self::reset_budget_ack_head_watermark(&transaction)?;
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

        let duplicate_event =
            if let Some(existing) = Self::load_mutation_event(transaction, &record.event_id)? {
                // A rolled-back authorize that the leader re-appended at a STRICTLY
                // HIGHER event_seq takes the replace path even when every other field
                // matches. `same_imported_mutation` compares authority/content only and
                // ignores event_seq, so a SAME-AUTHORITY retry (the leader kept its
                // lease, so the re-append is byte-identical apart from its fresh seq)
                // would otherwise be short-circuited as a duplicate below and the
                // follower would never store the re-appended row - stalling its
                // contiguous ack head at the rollback marker until a full snapshot
                // rebuild. Gating on `record.event_seq > existing.event_seq`
                // keeps this FORWARD-ONLY: a genuine idempotent re-delivery (equal seq)
                // or a stale lower-seq replay falls through to the duplicate no-op below
                // and never regresses or double-tombstones the head. This also covers the
                // cross-authority re-append (authority differs, so content differs), for
                // which the re-append is likewise at a fresh higher seq.
                if record.event_seq > existing.event_seq
                    && Self::rolled_back_authorize_can_be_replaced(transaction, &existing, record)?
                {
                    transaction.execute(
                        "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                        params![record.event_id],
                    )?;
                    // Symmetric with existing_event_allowed on the leader: the replaced
                    // old event's seq is genuinely superseded by the higher re-appended
                    // seq, so record it abandoned in the SAME transaction. An
                    // ALREADY-SYNCED follower (whose pull cursor is already past the old
                    // seq, so the delta's abandoned_seqs excludes it) then self-heals
                    // immediately - its contiguous ack head advances past the filled slot
                    // instead of stalling at the hole until a snapshot. Only the
                    // SPECIFICALLY-superseded seq is recorded (not an
                    // arbitrary gap), so a genuine missing event still caps the head;
                    // never over-counts.
                    if existing.event_seq > 0 && existing.event_seq != record.event_seq {
                        transaction.execute(
                            "INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq) VALUES (?1)",
                            params![existing.event_seq as i64],
                        )?;
                    }
                    Self::reset_budget_ack_head_watermark(transaction)?;
                    if let Some(hold_id) = record.hold_id.as_deref() {
                        transaction.execute(
                            "DELETE FROM budget_authorization_holds WHERE hold_id = ?1",
                            params![hold_id],
                        )?;
                    }
                    // Insert the incoming re-appended event (same event_id, fresh higher
                    // event_seq) AFTER tombstoning the superseded seq, so the follower
                    // actually holds the retried write. Without this insert the follower's
                    // contiguous ack head halts at the abandoned marker and never reaches
                    // the re-appended seq, so it never witnesses the retried write and
                    // quorum waits time out even though the delta was applied. This never
                    // over-counts: the superseded old seq stays abandoned (a
                    // FILLED-but-not-live slot, contributing no origin ack), while the
                    // re-appended event is a genuine leader-committed write, so witnessing
                    // its fresh seq is correct. A plain INSERT (mirroring the new-event
                    // path) is fail-closed: if a corrupt stream reused this fresh seq for a
                    // different event the unique event_seq index rejects it rather than
                    // masking it.
                    Self::insert_imported_mutation_event(transaction, record)?;
                    false
                } else if Self::same_imported_mutation(&existing, record) {
                    true
                } else {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget event_id `{}` was reused for a different mutation",
                        record.event_id
                    )));
                }
            } else {
                Self::insert_imported_mutation_event(transaction, record)?;
                false
            };

        if duplicate_event {
            return Ok(());
        }

        Self::apply_imported_hold_state(transaction, record)?;
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
            BudgetMutationKind::ExpireHold => {
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
                    HoldDisposition::Expired,
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
            // This is a GENUINE rollback-retry: the rolled-back authorize is
            // deleted and the caller re-appends it under a fresh higher seq. Record
            // the freed seq as abandoned/tombstoned BEFORE the delete so the global
            // contiguous ack head treats it as filled and does not stall cluster-
            // wide at the resulting hole. This recording is deliberately ONLY at the
            // rollback-retry site (not the AFTER DELETE trigger), so that a data-loss
            // delete still caps the head (fail-closed). Never over-counts: the
            // abandoned seq's write was superseded, so no live write targets it.
            let abandoned_seq: Option<i64> = transaction
                .query_row(
                    "SELECT event_seq FROM budget_mutation_events WHERE event_id = ?1",
                    params![event_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            transaction.execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )?;
            if let Some(seq) = abandoned_seq {
                if seq > 0 {
                    transaction.execute(
                        "INSERT OR IGNORE INTO budget_abandoned_event_seqs(seq) VALUES (?1)",
                        params![seq],
                    )?;
                }
            }
            Self::reset_budget_ack_head_watermark(transaction)?;
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
