# RFC-0007: Retention and compaction that preserve the append invariant

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0008 (checkpoint trigger strategy)
- Depends on: RFC-0006 (storage hot path: single writer, incremental head, audit demotion)
- Closes findings: F23, F24, F30 (see ./README.md and the readiness review)

## Summary

The SQLite receipt store has a retention path (`archive_receipts_before`,
`rotate_if_needed`) that copies aged receipts to an archive file and deletes the
source rows, but it never touches the `claim_receipt_log_entries` projection.
Because the claim log is a full-history re-derivation that the store cross-checks
by exact receipt-id set equality on every append, health, checkpoint, flush, and
at `open()`, the first successful rotation permanently bricks the store: every
write and every reopen fails with `claim receipt log entry set drift detected`,
and the failure survives restart with no in-code recovery. The retention machinery
is also dead code (never wired into the kernel), so the live database grows
without bound and is never vacuumed. This RFC makes archival co-archive and delete
the matching `claim_receipt_log_entries` rows (preserving their `entry_seq`) inside
one atomic, checkpoint-aligned transaction that temporarily drops and restores the
claim-log immutability triggers; teaches the projection backfill to refuse to
regenerate an archived or checkpointed range instead of guessing order; makes
checkpoint chain verification watermark-aware so checkpoints over archived ranges
are exempted from live Merkle rebuild (their deep verification serves from the
archive); wires
retention into the kernel through the single writer actor; and fixes the size
accounting so rotation converges (live-page size plus incremental vacuum). The
append path stays fail-closed and durable-before-allow.

## Motivation

Grounded in the readiness-review lens ("PostgreSQL and the OOM Killer"): a store
must fail early, local, and graceful, with a known blast radius, trustworthy
internal accounting, durable recovery, and predictable budgets. Retention
violates all five.

- F23 (high): retention deletes source rows but not the claim-log projection.
  Trigger: an operator enables retention or calls `archive_receipts_before` /
  `rotate_if_needed` on a live store and the first rotation completes. Effect:
  `chio_tool_receipts` and `chio_child_receipts` lose the archived rows, but
  `claim_receipt_log_entries` still holds them (the delete path never touches that
  table, and its own reject-delete trigger stays installed). The set-equality
  validator then finds "extra" claim-log ids forever. Blast radius: every
  subsequent append batch, every `append_chio_receipt_consuming_authorization`,
  `receipt_store_health`, `receipt_checkpoint_status`, `create_next_receipt_checkpoint`,
  and `flush_report` fail with `Conflict`; the default `SqliteReceiptStore::open()`
  also fails because open-time backfill runs the same validation. Because receipt
  persistence is a fail-closed pre-dispatch requirement, a kernel on this store
  stops serving tool calls entirely, and restart does not recover. Verified
  dynamically: after `archive_receipts_before(150, ...)` on an 11-receipt store,
  the next append, `receipt_store_health()`, and a fresh `open()` all returned the
  same drift error.

- F24 (high): retention is never wired, so the database grows without bound and is
  never vacuumed. Trigger: months of normal traffic on any durable store. Effect:
  `retention_config` is `None` at every construction site and nothing calls
  `rotate_if_needed`; there is no `VACUUM` or `auto_vacuum`, so even a manual
  archive would never shrink the file. Impact: disk exhaustion on the kernel host,
  and (compounded by F22, addressed in RFC-0006) superlinear append latency as the
  re-validated history grows. Second-order accounting bug: `db_size_bytes` counts
  freelist pages, so a size-triggered rotation that deletes rows but does not vacuum
  leaves the reported size above `max_size_bytes`, re-firing the trigger on every
  check (a Committed_AS-style measurement error) even before F23 bricks the store.

- F30 (medium, partial): the archive omits `claim_receipt_log_entries` entirely, so
  opening an archive rebuilds `entry_seq` by re-sorting on
  `(timestamp, kind_rank, source_seq, receipt_id)`, which is not the original commit
  order once child and tool receipts interleave under concurrency. Every co-archived
  checkpoint's Merkle root then fails to verify against the rebuilt log, and the
  original mapping was already deleted, so the archived tamper-evidence chain is
  permanently unverifiable. The checkpoint co-archival gate also compares an
  `entry_seq`-domain value (`batch_end_seq`) against a source-seq-domain value
  (`MAX(seq)` of `chio_tool_receipts`), a second domain mismatch once child receipts
  exist.

## Current behavior (verified 2026-07-04)

The retention entry points live in
`crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs`:

```rust
// evidence_retention.rs:93
pub fn archive_receipts_before(
    &mut self,
    cutoff_unix_secs: u64,
    archive_path: &str,
) -> Result<u64, ReceiptStoreError> { /* -> archive_receipts_before_scoped(.., None) */ }

// evidence_retention.rs:406
pub fn rotate_if_needed(&mut self, config: &RetentionConfig) -> Result<u64, ReceiptStoreError>
```

`archive_receipts_before_scoped` (evidence_retention.rs:112) acquires
`let connection = self.connection()?;`. That accessor returns a connection from the
**reader** pool (`receipt_store.rs:490`, `self.pool.get()`; `self.pool` is bound to
`reader_pool` in `bootstrap/open.rs:1075`), so retention currently writes through the
reader pool, violating the single-writer discipline RFC-0006 establishes. It then
`ATTACH`es the archive, creates exactly four archive tables (evidence_retention.rs:127-182:
`chio_tool_receipts`, `chio_child_receipts`, `kernel_checkpoints`, `capability_lineage`;
there is no archive table for `claim_receipt_log_entries`, `settlement_reconciliations`,
`metered_billing_reconciliations`, or `chio_authorization_receipt_consumptions`), copies
qualifying receipts with `INSERT OR IGNORE`, and copies checkpoints whose
`batch_end_seq <= max_archived_seq`, where `max_archived_seq` is
`SELECT MAX(seq) FROM main.chio_tool_receipts WHERE timestamp < ?1`
(evidence_retention.rs:251-256) - a source-seq value compared against an `entry_seq`
value (F30).

`delete_archived_live_receipts` (evidence_retention.rs:320) then runs:

```rust
// evidence_retention.rs:325
connection.execute_batch(
    r#"
    DROP TRIGGER IF EXISTS chio_child_receipts_reject_delete;
    DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete;
    "#,
)?;
// ... DELETE FROM main.chio_child_receipts / main.chio_tool_receipts ...
let restore_result = ensure_transparency_projection_guards(connection);
```

It drops only the two receipt-table reject-delete triggers, deletes only from those two
tables, and never deletes from `claim_receipt_log_entries`. The claim-log
reject-update/reject-delete triggers (`checkpoint_projection.rs:28-38`) stay installed the
whole time, and the projection keeps the archived ids, because the AFTER INSERT projection
triggers (`bootstrap/open.rs:676-708`, `:711-743`) are insert-only.

The validator that turns this into a brick is
`validate_or_backfill_claim_receipt_log_entries`
(`support/claim_log/validation.rs:15`, reached on the hot paths through its thin
wrapper `validate_claim_receipt_log_entries` at `validation.rs:9`):

```rust
// validation.rs:80
let existing_receipt_ids = load_claim_receipt_log_receipt_ids(connection)?;
if existing_receipt_ids != expected_receipt_ids {
    // ... -> ReceiptStoreError::Conflict(
    //        "claim receipt log entry set drift detected (missing: .., extra: ..)")
}
```

`expected_receipt_ids` is derived from a full scan of both source tables
(`checkpoint_projection.rs:172-276`). After archival the source tables shrink but the claim
log does not, so the archived ids show up as `extra` and the check fails. This exact call
sits on every hot path:

- `append_receipt_batch` (`receipt_store.rs:392`)
- `append_chio_receipt_consuming_authorization` (`receipt_store.rs:589`)
- `receipt_store_health` via `validate_claim_receipt_log_projection_current` (`receipt_store.rs:615`, `:763`)
- `receipt_checkpoint_status` (`receipt_store.rs:671`)
- `create_next_receipt_checkpoint` (`receipt_store.rs:732`)
- `flush_report` (`receipt_store.rs:740`)

A second validator family walks the checkpoint chain and imposes the same
full-history requirement. `verify_checkpoint_chain_integrity`
(`support/checkpoint_validate.rs:286`) loads every persisted checkpoint row and, for
each one, calls `validate_checkpoint_against_claim_log` (`checkpoint_validate.rs:345`),
which Merkle-rebuilds the checkpoint's `[batch_start_seq, batch_end_seq]` range via
`load_claim_tree_canonical_bytes_range` (`checkpoint_projection.rs:416`); that helper
first enforces `ensure_claim_log_range_contiguous` (`checkpoint_projection.rs:421`).
This full-chain walk runs on every append through `verify_latest_checkpoint_integrity`
(`checkpoint_validate.rs:277`, called at `receipt_store.rs:401` and `:591`), inside
`create_next_receipt_checkpoint_atomic` (`checkpoint_validate.rs:400`, `:465-475`), and
in `receipt_checkpoint_status` (`receipt_store.rs:674`). Any checkpoint whose covered
claim-log rows are missing fails the whole chain, so deleting archived claim-log rows
while their checkpoints remain in `main.kernel_checkpoints` is a second, independent
brick; section 4 of the design addresses it.

Reopen also fails. `open()` sets `create_if_missing = true`
(`bootstrap/open.rs:49`, `:71`) and runs
`backfill_claim_receipt_log_entries` (`bootstrap/open.rs:1042`). Its repair branch only
fires when the projection is completely empty (`validation.rs:47-62`); post-archival the
projection is non-empty, so control falls through to the same set-equality check and `open()`
aborts. Only `open_existing()` (`bootstrap/open.rs:53`, `create_if_missing = false`, early
return at `:102-126`) skips the backfill, which is why `chio receipt list/explain` still read
while all writes and `open()` fail.

Wiring status confirmed: `KernelConfig.retention_config`
(`crates/kernel/chio-kernel/src/kernel/kernel_struct.rs:59`,
`Option<crate::receipt_store::RetentionConfig>`) is read by nothing; every construction site
sets `None`. The only callers of `archive_receipts_before*` / `rotate_if_needed` are in
`crates/kernel/chio-kernel/tests/retention.rs`. `RetentionConfig`
(`crates/kernel/chio-kernel/src/receipt_store.rs:16-37`) defaults to
`retention_days: 90`, `max_size_bytes: 10_737_418_240`,
`archive_path: "receipts-archive.sqlite3"`, `tenant_id: None`. `db_size_bytes`
(`evidence_retention.rs:51-59`) returns `page_count * page_size`, freelist pages included.
There is no `auto_vacuum` or `VACUUM` anywhere (`bootstrap/open.rs:6-9` sets only WAL,
`synchronous = FULL`, `busy_timeout`, `foreign_keys = ON`).

The existing tests pass only because `retention.rs` never appends to or reopens the **live**
store after archival; it counts rows and opens the **archive** file, which backfills from an
empty projection.

## Design

The core principle: the claim log must remain a faithful projection of the source tables at
all times, so retention must remove receipts from the projection and the source tables
together, atomically, and only along checkpoint boundaries. Everything else (validator
hardening, kernel wiring, size accounting, recovery) follows from keeping that invariant true.

### 1. Checkpoint-aligned archival watermark (entry_seq domain)

Archival is expressed as a single monotone `entry_seq` watermark `W`. `W` is the largest
checkpoint `batch_end_seq` whose entire covered prefix has aged past the cutoff:

```sql
-- All rows in [1, W] are age-eligible AND fully covered by a co-archived checkpoint.
SELECT COALESCE(MAX(kc.batch_end_seq), 0)
FROM kernel_checkpoints kc
WHERE NOT EXISTS (
    SELECT 1
    FROM claim_receipt_log_entries e
    WHERE e.entry_seq <= kc.batch_end_seq
      AND e.timestamp >= ?cutoff
);
```

This computes `W` entirely in the `entry_seq` domain (fixing the F30 co-archival gate),
uses `MAX(timestamp)` over the whole prefix rather than the boundary row's timestamp (so a
non-monotonic timestamp inside the prefix cannot smuggle an unaged receipt into the archive),
and guarantees `W <= latest_checkpointed_entry_seq`. Since checkpoints cover a contiguous
prefix `[1, batch_end_seq]` (ADR-0008 count-based batches) and only whole batches archive,
the archived range is always `[1, W]` and never overlaps the uncheckpointed suffix that the
hot paths read. If `W == 0` the rotation is a no-op (fail-safe: nothing is deleted until a
checkpoint has committed the range).

Because `W <= latest_checkpointed_entry_seq`, `ensure_claim_log_range_contiguous`
(`receipt_store.rs:830`) is always evaluated over `[latest_checkpointed_entry_seq + 1,
latest_committed_entry_seq]`, which is untouched, so health, checkpoint status, and
`load_claim_tree_canonical_bytes_range` keep passing.

Tenant-scoped archival is incompatible with this invariant and is rejected
fail-closed. `archive_receipts_before_for_tenant` (evidence_retention.rs:103) and
`RetentionConfig.tenant_id: Some(..)` select a non-prefix subset of the claim log;
deleting it cannot be expressed as an `entry_seq` watermark and would punch holes
inside checkpointed ranges. Under this RFC a tenant-scoped rotation returns
`RetentionTenantScopeUnsupported` without modifying anything (consistent with the
fail-closed posture: an unsupportable retention request denies rather than corrupts).
A tenant-aware design (per-tenant claim logs or checkpoint partitioning) is future
work and out of scope here.

### 2. Co-archive-and-delete inside one transaction

Add `claim_receipt_log_entries` (with `entry_seq` preserved),
`settlement_reconciliations`, `metered_billing_reconciliations`, and
`chio_authorization_receipt_consumptions` to the archive schema
(evidence_retention.rs:127) so archived checkpoints re-verify (F30) and reconciliation
evidence is not silently lost (F23 side hazard). The archive `claim_receipt_log_entries`
table keeps the same DDL as `bootstrap/open.rs:628-663`, including
`entry_seq INTEGER PRIMARY KEY` (not `AUTOINCREMENT`, so copied values are inserted verbatim).

The new flow (`archive_range`, replacing `delete_archived_live_receipts`) runs on the writer
connection:

1. `ATTACH DATABASE '<escaped>' AS archive;` (outside any transaction; `ATTACH` cannot run
   inside one).
2. Create archive tables if missing; `INSERT OR IGNORE` copy, all keyed by `W`:
   `claim_receipt_log_entries WHERE entry_seq <= W`; the `chio_tool_receipts` /
   `chio_child_receipts` rows those entries reference; `kernel_checkpoints WHERE
   batch_end_seq <= W`; `capability_lineage` for the archived receipts; and the
   reconciliation and consumption rows for the archived `receipt_id`s.
3. Verify co-archival completeness by count (checkpoints, receipts, reconciliation rows,
   consumptions). Any shortfall returns a typed error and aborts before any delete
   (fail-closed, preserving inclusion-proof integrity).
4. `BEGIN IMMEDIATE;` on the writer connection, then, all within that one transaction
   (SQLite executes `CREATE`/`DROP TRIGGER` transactionally, so a rollback restores triggers
   and rows together):

```sql
DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete;
DROP TRIGGER IF EXISTS chio_child_receipts_reject_delete;
DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;

-- FK-safe order (foreign_keys = ON): dependents before parents.
DELETE FROM settlement_reconciliations       WHERE receipt_id IN (<archived tool ids>);
DELETE FROM metered_billing_reconciliations  WHERE receipt_id IN (<archived tool ids>);
DELETE FROM chio_authorization_receipt_consumptions
    WHERE authorization_receipt_id IN (<archived tool ids>);      -- ON DELETE RESTRICT
DELETE FROM claim_receipt_log_entries WHERE entry_seq <= ?W;
DELETE FROM chio_child_receipts  WHERE seq IN (<archived child seqs>);
DELETE FROM chio_tool_receipts   WHERE seq IN (<archived tool seqs>);

INSERT INTO receipt_retention_watermark
    (archived_through_entry_seq, archived_through_timestamp, archive_path, archive_sha256, rotated_at)
    VALUES (?W, ?cutoff, ?path, ?sha, ?now);

-- Recreate immutability guards inside the same transaction.
CREATE TRIGGER IF NOT EXISTS chio_tool_receipts_reject_delete /* ... */;
CREATE TRIGGER IF NOT EXISTS chio_child_receipts_reject_delete /* ... */;
CREATE TRIGGER IF NOT EXISTS claim_receipt_log_entries_reject_delete /* ... */;
```

5. `COMMIT;` On any error, `ROLLBACK` restores the archived rows and the three triggers
   atomically (this is strictly stronger than today's out-of-transaction drop/restore dance
   at evidence_retention.rs:325-396, where a mid-delete failure could leave the receipt tables
   without their immutability guards until the next `open()`).
6. `DETACH DATABASE archive;`
7. `PRAGMA incremental_vacuum;` then `PRAGMA wal_checkpoint(TRUNCATE);` to reclaim freelist
   pages and shrink the file.

Cross-database atomicity note: in WAL mode a transaction spanning `main` and an attached
database is atomic per-database, not across both. This design never needs cross-database
atomicity: the copy (step 2) is idempotent (`INSERT OR IGNORE`) and completes before any
delete, and the delete (step 4) touches only `main`, so it is atomic on the live database.
A crash between copy and delete leaves the live store fully intact and the rotation re-runnable.

After step 2 succeeds and step 4 commits, the source tables and the claim log have both lost
exactly the same `receipt_id` set, so the set-equality validator (`validation.rs:80`) passes
with no change to its comparison. The claim log stays a faithful projection.

### 3. Validator hardening: refuse to regenerate an archived or checkpointed range

The reopen brick has a second, independent form: if the claim log is ever empty on a store
that has already checkpointed or archived (for example after a botched manual repair), the
backfill would regenerate `entry_seq` from the surviving source rows in
`(timestamp, kind_rank, source_seq, receipt_id)` order, silently assigning fresh sequence
numbers that no longer line up with the checkpoint `batch_end_seq` boundaries (F30). Retention
must never depend on that guess. Change `validate_or_backfill_claim_receipt_log_entries`
(`validation.rs:15`) so the empty-projection repair only fires on a pristine store:

```rust
if existing_count == 0 {
    if !repair_empty_projection {
        if expected.is_empty() {
            return Ok(());
        }
        return Err(ReceiptStoreError::Conflict(
            "claim receipt log projection is missing for persisted receipt rows".to_string(),
        ));
    }
    // NEW (fail-closed): only regenerate a never-checkpointed, never-archived log.
    // `kernel_checkpoints_exist` and `retention_watermark` are new small query helpers.
    let watermark = retention_watermark(connection)?;
    if kernel_checkpoints_exist(connection)? || watermark.is_some() {
        return Err(ReceiptStoreError::ArchivedRangeProjection {
            watermark: watermark.unwrap_or(0),
        });
    }
    let tx = connection.unchecked_transaction()?;
    for row in &expected {
        insert_claim_receipt_log_projection_row(&tx, row)?;
    }
    tx.commit()?;
    return Ok(());
}
```

With the co-archive path in place, the normal post-archival log is non-empty and reaches the
unchanged set-equality branch, which now passes; this hardening only guards the empty-projection
regeneration so it can never fabricate an order over a range that a checkpoint or archive has
already fixed. `RFC-0006` demotes the full set-equality validator off the append hot path into
`chio receipt audit` and the one-time `seed_verified_head`; both call the same function, so this
single change covers audit, seed, and the residual open-time path.

### 4. Watermark-aware checkpoint chain verification

Co-archive-and-delete alone swaps the set-equality brick for a chain-integrity
brick. The archived checkpoints stay in `main.kernel_checkpoints` (and must:
`validate_checkpoint_base` at `checkpoint_validate.rs:324` requires the first
checkpoint to sit at `checkpoint_seq 1` / `batch_start_seq 1`, and the predecessor
chain anchors there, so retention never deletes checkpoint rows; they are small).
But `verify_checkpoint_chain_integrity` (`checkpoint_validate.rs:286`) rebuilds every
checkpoint's Merkle root from live claim-log rows, and after archival those rows are
gone for every checkpoint with `batch_end_seq <= W`. Without a change, the next
`create_next_receipt_checkpoint` (via `checkpoint_validate.rs:400`), every
`receipt_checkpoint_status`, RFC-0006's `seed_verified_head` at `open()`, and
`chio receipt audit` all fail, W never advances, and the reopen brick returns in a
new form.

Fix: make the chain walk watermark-aware. `verify_checkpoint_chain_integrity` loads
`W = COALESCE(MAX(archived_through_entry_seq), 0)` from `receipt_retention_watermark`
once per walk. For checkpoints with `batch_end_seq <= W` it still parses and
validates the signed body, signature, and column consistency
(`parse_persisted_checkpoint_row`, `checkpoint_validate.rs:210`), still validates the
transparency projection rows, and still validates predecessor linkage (none of which
reads the claim log); it skips only `validate_checkpoint_against_claim_log` (the
live Merkle rebuild). Checkpoints with `batch_end_seq > W` verify exactly as today.
Because `W` is always some checkpoint's `batch_end_seq` and batches tile the prefix
contiguously (ADR-0008), no checkpoint range ever straddles the watermark, so the
exemption is all-or-nothing per checkpoint. Deep Merkle re-verification of exempted
checkpoints is served from the archive, whose preserved `entry_seq` mapping
reproduces the roots (section 2). The exemption stays fail-closed: it applies only
to ranges that a persisted watermark row attests were co-archived, and it never
weakens verification of anything above `W`.

### 5. New types, signatures, and config

```rust
// crates/kernel/chio-kernel/src/receipt_store.rs (extend RetentionConfig)
pub struct RetentionConfig {
    pub retention_days: u64,          // default 90 (unchanged)
    pub max_size_bytes: u64,          // default 10_737_418_240 (unchanged)
    pub archive_path: String,         // default "receipts-archive.sqlite3" (unchanged)
    pub tenant_id: Option<String>,    // unchanged
    /// How often the kernel evaluates rotation. Default: 3600s.
    pub check_interval_secs: u64,     // NEW, default 3_600
}

// crates/platform/chio-store-sqlite/src/receipt_store.rs (writer-actor command)
enum ReceiptCommitCommand {
    Append(Box<ReceiptCommitRequest>),
    Flush(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
    Rotate {                                   // NEW
        config: Box<RetentionConfig>,
        response: mpsc::SyncSender<Result<u64, ReceiptStoreError>>,
    },
}

// Public API: change &mut self -> &self; dispatch the mutation to the single writer actor.
pub fn rotate_if_needed(&self, config: &RetentionConfig) -> Result<u64, ReceiptStoreError>;
pub fn archive_receipts_before(&self, cutoff_unix_secs: u64, archive_path: &str)
    -> Result<u64, ReceiptStoreError>;

// New size accounting used by the rotation trigger.
pub fn live_db_size_bytes(&self) -> Result<u64, ReceiptStoreError>; // (page_count - freelist_count) * page_size
```

`rotate_if_needed` sends `Rotate` to the actor and blocks on the response; the actor drains
any in-flight append batch, then runs `archive_range` on the writer connection. Because the
actor thread is the only writer, rotation is serialized with appends without a second lock,
which also removes the current reader-pool-write bug. `live_db_size_bytes` computes
`(page_count - freelist_count) * page_size`; the `rotate_if_needed` size trigger uses it so a
size-driven archive plus `incremental_vacuum` strictly reduces the measured value and the
trigger converges instead of re-firing (fixes the F24 accounting loop). `db_size_bytes`
(on-disk, freelist included) is retained for reporting.

Error taxonomy (extend `ReceiptStoreError`, all fail-closed):

```rust
/// Co-archival did not transfer every dependent row; no delete was performed.
RetentionArchiveIncomplete { table: &'static str, live: u64, archived: u64 },
/// A rotation attempted a watermark below the persisted high-water mark.
RetentionWatermarkRegression { attempted: u64, current: u64 },
/// Backfill was asked to regenerate a projection over a checkpointed/archived range.
ArchivedRangeProjection { watermark: u64 },
/// Tenant-scoped rotation is not expressible as a prefix watermark; nothing was modified.
RetentionTenantScopeUnsupported,
```

### 6. Kernel wiring (F24)

`ChioKernel` reads `KernelConfig.retention_config`. When `Some(config)`, at startup it spawns
one maintenance task that sleeps `check_interval_secs` and calls
`store.rotate_if_needed(&config)`, logging the archived count and surfacing errors to health
(the task never panics; a rotation error is recorded and retried next interval, and it never
blocks dispatch). When `None`, behavior is unchanged (retention disabled), but health
(`ReceiptStoreHealthReport` already carries `db_size_bytes`, receipt_store.rs:645) gains
`retention_watermark_entry_seq` so unbounded growth is visible and
alertable even without archival enabled. `auto_vacuum` is set to `INCREMENTAL` at creation for
new stores (`bootstrap/open.rs:6-9`); existing stores are migrated once (detect
`PRAGMA auto_vacuum == 0`, set `INCREMENTAL`, run a single `VACUUM` on the drained writer at
first maintenance pass) so `incremental_vacuum` can reclaim pages thereafter.

### 7. Recovery for an already-bricked store

A store archived under the pre-fix code has surviving `extra` claim-log entries and fails every
write and `open()`. Two recovery routes:

- Restore from backup. This remains the safest route and is the only one available today.
- `chio receipt retention repair --archive <path>` (new, fail-closed):
  1. Open via `open_existing` (skips backfill, so the tool itself does not brick).
  2. Compute the `extra` set = claim-log `receipt_id`s absent from both source tables.
  3. Assert every `extra` id is present in the named archive file, and every such
     `entry_seq <= latest_checkpointed_entry_seq`. If either check fails, abort without
     modifying the store (do not delete an entry that was not genuinely archived, and never
     touch the uncheckpointed suffix).
  4. On the writer connection, in one `BEGIN IMMEDIATE` transaction: drop the claim-log
     reject-delete trigger, delete the `extra` rows, insert the `receipt_retention_watermark`
     row, recreate the trigger, commit. The recorded `archived_through_entry_seq` is the
     smallest checkpoint `batch_end_seq >= max(extra.entry_seq)` (checkpoint-aligned
     rounding): pre-fix archival selected by timestamp, so the `extra` set need not end on
     a batch boundary, and an unrounded watermark would leave a straddling checkpoint
     non-exempt under section 4 with holes in its range. Live claim-log rows at or below
     the rounded watermark (whose source receipts survived) are retained; they are exempt
     from live chain rebuild and are swept into the archive by the next normal rotation.
  5. `PRAGMA incremental_vacuum; PRAGMA wal_checkpoint(TRUNCATE);`

After repair, set-equality holds, `open()` succeeds, and appends resume. Because only
checkpoint-covered entries are removed, the contiguity checks (`receipt_store.rs:830`) that the
uncheckpointed suffix relies on are never tripped.

## Wire, schema, and receipt impact

- Signed payloads: none. Receipt bodies and `KernelCheckpoint` wire forms are unchanged.
  Archived `raw_json` is copied verbatim, so RFC 8785 canonical JSON leaf hashing over archived
  claim-log entries reproduces the co-archived checkpoint Merkle roots exactly.
- New table (main DB), append-only operational metadata:
  `receipt_retention_watermark(archived_through_entry_seq INTEGER NOT NULL, archived_through_timestamp INTEGER NOT NULL, archive_path TEXT NOT NULL, archive_sha256 TEXT, rotated_at INTEGER NOT NULL)`.
  It is a ledger; the effective watermark is `MAX(archived_through_entry_seq)`, and a rotation
  that would lower it returns `RetentionWatermarkRegression`.
- Archive schema (evidence_retention.rs:127) gains `claim_receipt_log_entries` (with `entry_seq`
  preserved, no `AUTOINCREMENT`), `settlement_reconciliations`, `metered_billing_reconciliations`,
  and `chio_authorization_receipt_consumptions`.
- `RetentionConfig` gains `check_interval_secs` (default 3600). No serialized wire form of
  `RetentionConfig` exists today, so this is an additive Rust-struct change only.

## Migration and compatibility

- All new tables use `CREATE TABLE IF NOT EXISTS`; a store with no watermark row has simply
  never archived, and every existing store opens unchanged.
- Retention stays feature-flagged by `retention_config`: `None` preserves today's
  (unbounded-growth) behavior; `Some` enables archival plus vacuuming.
- Archives produced by the pre-fix code lack the co-archived claim-log `entry_seq` mapping and
  cannot be Merkle-verified; the reader detects a missing archive `claim_receipt_log_entries`
  table and refuses to treat those archives as verifiable, directing operators to re-archive
  from a restored live store.
- Staged rollout: RFC-0006 lands first (single writer, incremental head, audit demotion). Then
  this RFC lands the co-archive-and-delete path plus validator hardening with retention still
  defaulting to `None`. Kernel wiring and `auto_vacuum` migration land last, enabled per
  deployment.

## Test and verification plan

Ties into the wave-3 load-chaos program and the formal-methods plan.

- Proptest state-machine (formal plan), the primary proof:
  `prop_retention_preserves_append_invariant`. Model a sequence of appends (interleaved tool
  and child receipts, non-monotonic timestamps), checkpoint creations, and rotations. After any
  reachable sequence assert: (1) the next append succeeds; (2) `open()` reopen succeeds; (3)
  `receipt_store_health()` is healthy; (4) live set-equality holds; (5) archived and live
  `receipt_id` sets partition the full history with no overlap or gap; (6) every co-archived
  checkpoint's Merkle root re-verifies against the archived `claim_receipt_log_entries`
  `entry_seq`. This is the test that would have caught F23, F30, and the reopen brick.
- The specific regression the finding says is missing:
  `retention_then_append_and_reopen_succeeds` (append, checkpoint, `archive_receipts_before`,
  then append again and `open()` again on the live store, all succeed).
- Chain verification across the watermark: `checkpoint_chain_watermark_exemption` (after a
  rotation, `create_next_receipt_checkpoint`, `receipt_checkpoint_status`, `chio receipt
  audit`, and reopen via `seed_verified_head` all succeed; a tampered claim-log row ABOVE
  the watermark still fails the chain, proving the exemption does not weaken live
  verification; a forged watermark row without matching archive contents is caught by
  audit against the archive).
- Tenant scope fail-closed: `tenant_scoped_rotation_rejected` (rotation with
  `tenant_id: Some(..)` returns `RetentionTenantScopeUnsupported` and modifies nothing).
- Recovery: `bricked_store_repair_restores_append` (produce a store bricked under the old delete
  path via a fixture, run `retention repair`, assert append and `open()` succeed and only
  checkpoint-covered entries were removed).
- Accounting convergence: `size_rotation_converges_below_threshold` (drive
  `db_size_bytes > max_size_bytes`, assert `live_db_size_bytes` drops below the threshold after
  one rotation and the trigger does not re-fire).
- Reconciliation evidence: `settlement_and_metered_rows_are_archived_not_cascaded` (assert the
  reconciliation and consumption rows land in the archive and are absent from live, never
  silently cascaded away).
- Fail-closed backfill: `backfill_refuses_regeneration_over_checkpointed_range` (empty the
  projection on a checkpointed store, assert `open()` returns `ArchivedRangeProjection`, not a
  regenerated log).
- loom: model the writer actor with concurrent `Append` and `Rotate`; assert single-writer
  serialization and no lost `inflight` accounting (the pre-send increment invariant at
  `receipt_store.rs:177` must hold across `Rotate`).
- Soak / chaos (load-chaos program): `soak_rotation_under_continuous_append` (continuous appends
  with periodic checkpoints and rotations for 10M receipts; assert flat per-append p99, bounded
  file size, zero drift errors, zero reopen failures).

## Acceptance criteria

- After `archive_receipts_before` / `rotate_if_needed` on a live store, the next append,
  `append_chio_receipt_consuming_authorization`, `receipt_store_health`,
  `receipt_checkpoint_status`, `create_next_receipt_checkpoint`, `flush_report`, and a fresh
  `open()` all succeed.
- Live set-equality holds after archival; archived and live `receipt_id` sets partition the full
  history; the archived range is checkpoint-aligned (`W <= latest_checkpointed_entry_seq`).
- Every co-archived checkpoint re-verifies against the archived `entry_seq` mapping.
- After rotation, `create_next_receipt_checkpoint` and `chio receipt audit` succeed:
  chain verification exempts exactly the checkpoints with `batch_end_seq <=` the persisted
  watermark and verifies everything above it unchanged.
- A rotation with `RetentionConfig.tenant_id: Some(..)` is rejected with
  `RetentionTenantScopeUnsupported` and leaves the store unmodified.
- The empty-projection backfill refuses to regenerate a checkpointed or archived range and
  returns `ArchivedRangeProjection` (fail-closed) instead of guessing order.
- With `retention_config = Some`, the file size stays bounded and the size trigger converges
  (no re-fire loop); `incremental_vacuum` runs after each archival delete.
- Reconciliation and consumption rows are co-archived, not silently lost.
- `chio receipt retention repair` restores a store bricked under the old path to a writable state
  without touching the uncheckpointed suffix.
- Retention mutations execute only on the writer actor; a test asserts the reader pool never
  begins a write transaction for archival (consistent with RFC-0006).

## Risks and alternatives

- Validator-exemption-only (keep archived claim-log rows, teach the validator a watermark that
  exempts `entry_seq <= W` from set-equality) was considered and rejected as the primary design:
  it leaves the claim log growing without bound (the projection is the largest table and would
  never shrink), defeats the retention goal, and threads watermark logic through every validator
  and through `seed_verified_head`. The co-archive-and-delete path keeps the projection a faithful
  mirror, so set-equality needs no exemption; the remaining validator changes are the fail-closed
  regeneration guard (section 3) and the checkpoint-chain watermark exemption (section 4). The
  latter is unavoidable in any design that removes archived claim-log rows while retaining the
  checkpoint spine, and it is narrower than a set-equality exemption: it skips only the live
  Merkle rebuild for ranges a persisted watermark attests were co-archived.
- Full `VACUUM` versus `incremental_vacuum`: a full `VACUUM` rewrites the whole file under an
  exclusive lock and needs up to 2x free disk, stalling the writer. `incremental_vacuum` reclaims
  only the freelist pages produced by the archival delete without a full rewrite, so it is the
  default; a full `VACUUM` is reserved for the one-time `auto_vacuum` migration on the drained
  writer.
- Cross-database WAL atomicity: mitigated structurally by copy-then-delete ordering and by keeping
  the delete confined to `main`, so no cross-database atomic commit is ever required.
- Serving inclusion proofs for the archived range from the live database is no longer possible
  (its claim-log rows are gone); proofs for archived receipts are served from the archive file,
  whose preserved `entry_seq` reproduces the checkpoint roots. This is the intended trade: the live
  database holds recent history at bounded size; the archive holds verifiable cold history.
- Throughput: rotation runs on the writer actor and briefly pauses appends during the delete plus
  `incremental_vacuum`. Bounded by `check_interval_secs` (default hourly) and by archiving only
  checkpoint-aligned prefixes, so the pause is proportional to the batch size deleted, not to total
  history; the soak test asserts flat append latency across rotations.

## Rollout and sequencing

RFC-0006 must land first: this RFC runs archival on the single writer actor RFC-0006 introduces,
relies on its incremental verified head and on `chio receipt audit` for the full set-equality
check, and reuses its writer-drain semantics for `Rotate` and `VACUUM`. Sequence: (1) RFC-0006;
(2) archive-schema additions, `archive_range` co-archive-and-delete, entry_seq watermark,
watermark-aware chain verification, and the
fail-closed backfill guard, with retention still defaulting to `None` (these land together:
deleting claim-log rows without the chain exemption re-bricks the store); (3) `RetentionConfig`
extension, kernel maintenance task, `auto_vacuum`/size-accounting changes, and the
`retention repair` recovery command. This RFC extends ADR-0008: the checkpoint batch is the atomic
unit of archival, so count-based checkpoints double as the compaction boundary and no time-based
trigger is introduced.
