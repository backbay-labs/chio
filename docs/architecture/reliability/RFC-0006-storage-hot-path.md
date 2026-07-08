# RFC-0006: Storage hot path: incremental chain verification, background checkpoints, single writer

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0008 (checkpoint trigger strategy), ADR-0013 (async receipt durability)
- Depends on: none
- Closes findings: F22, F28, F29, F07 (see ./README.md and the readiness review)

## Summary

The SQLite receipt store re-validates the entire receipt history on every
append. Each committed batch runs a full two-table projection scan plus a
full checkpoint-chain rebuild (per-checkpoint signature checks, per-batch
Merkle reconstruction, and roughly two Ed25519 verifications per historical
receipt), and it does so inside the kernel-global receipt-store write lock.
Checkpoint creation runs the same O(N) work synchronously on the request
path, and many writes that should be serialized through the single writer
instead flow through the read pool. This RFC replaces per-append full-history
verification with an incremental verified-head check (per-append work bounded
by batch size, not history), moves checkpoint construction onto a background writer task off the
request path and out from under the global lock, and routes every write
through one writer connection so the reader pool is strictly read-only. Full
verification is demoted to an explicit `chio receipt audit` CLI and a
one-time startup verification that seeds the verified head. The append path
stays fail-closed and durable-before-allow, preserving ADR-0013.

## Motivation

Grounded in the readiness review lens ("PostgreSQL and the OOM Killer"):
overload must fail early, local, and graceful, with a known blast radius,
trustworthy internal accounting, and predictable budgets. The receipt store
violates all of these as the log grows.

- F22 (high): every append re-validates the whole history. Trigger: normal
  receipt accumulation in any deployment with a durable store. Effect:
  `append_receipt_batch` runs `validate_claim_receipt_log_entries` (a full
  scan of both source tables plus a point query per row and a whole-log
  `BTreeSet` set-equality) and `verify_latest_checkpoint_integrity` (a full
  chain rebuild) before every batch. At N receipts with batch size 100 that
  is N/100 checkpoint signature checks, N/100 Merkle rebuilds, and roughly
  2N Ed25519 verifications per append. Impact: at ~1M receipts an append
  implies ~2M signature verifications (minutes of CPU), so dispatch, health,
  flush, and checkpoint creation collapse together and the kernel stops
  serving long before typical infrastructure data volumes.

- F28 (high) and F07 (medium): checkpoint creation runs inline on the request
  path under the global write lock. Every 100th append synchronously performs
  O(total-history) verification inside `receipt_store_write_lock` and an
  IMMEDIATE SQLite write transaction. Blast radius: that agent's tool call
  stalls; all concurrent receipt persistence for all tenants stalls behind
  the mutex; all other DB writers stall behind the SQLite write lock
  (`busy_timeout` 5000ms, then `SQLITE_BUSY`). Once a single checkpoint
  exceeds ~5s the failures land after tool side effects have already run.

- F29 (high): single-writer discipline is incomplete. Session anchors,
  request lineage, receipt-lineage statements, child receipts,
  consuming-authorization appends, checkpoint creation, and IOU writes all
  run IMMEDIATE write transactions on connections drawn from the reader pool.
  Under the F28-induced long writer holds these exhaust `busy_timeout` and
  fail with `SQLITE_BUSY` after side effects. The trait append commits the
  receipt through the actor and then writes lineage in a separate later
  transaction that can independently fail, leaving receipt-without-lineage
  state (untrustworthy internal accounting).

Blast radius in one line: trigger is routine receipt accumulation; effect is
unbounded per-append CPU and memory plus cross-tenant write stalls and
partial writes; who is impacted is every tenant of a kernel with a durable
receipt store.

## Current behavior (verified 2026-07-04)

All paths below were re-read against the working tree.

Append fast path, `crates/platform/chio-store-sqlite/src/receipt_store.rs`:

```rust
// receipt_store.rs:376
fn append_receipt_batch(
    pool: &Pool<SqliteConnectionManager>,
    requests: &[ReceiptCommitRequest],
) -> Vec<Result<u64, ReceiptStoreError>> {
    // ...
    // :389 guards
    if let Err(error) = ensure_checkpoint_transparency_guards(&connection) { /* ... */ }
    // :392 FULL two-table projection scan + point query per row + set-equality
    if let Err(error) = validate_claim_receipt_log_entries(&connection) { /* ... */ }
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // :401 FULL checkpoint-chain rebuild
    if let Err(error) = verify_latest_checkpoint_integrity(&tx) { /* ... */ }
    // :405 append the batch
    // ...
}
```

`validate_claim_receipt_log_entries`
(`receipt_store/support/claim_log/validation.rs:9`) loads every row of both
source tables into a `Vec` (lines 19-20), sorts (21-34), counts (36-41),
builds a `BTreeSet` of every receipt id (42-45), runs one point query per
expected row (64-78), and asserts full set equality
`existing_receipt_ids != expected_receipt_ids` (80-95).

`verify_latest_checkpoint_integrity`
(`receipt_store/support/checkpoint_validate.rs:277`) short-circuits only when
no checkpoint exists; otherwise it calls `verify_checkpoint_chain_integrity`
(`checkpoint_validate.rs:286`), which loads every persisted checkpoint row
(`load_all_persisted_checkpoint_rows`), and for each one runs
`validate_checkpoint_against_claim_log` (line 297) that reloads the batch
range, rebuilds the Merkle tree (`MerkleTree::from_leaves`, line 366), and
compares the root, plus predecessor linkage (306) across the whole chain.

The single writer is a group-commit actor. The store holds two pools:

```rust
// receipt_store.rs:103
pub struct SqliteReceiptStore {
    pub(crate) pool: Pool<SqliteConnectionManager>,       // reader pool
    receipt_commit_actor: ReceiptCommitActor,             // owns the writer pool
    pub(crate) strict_tenant_isolation: std::sync::atomic::AtomicBool,
}

// receipt_store.rs:147
enum ReceiptCommitCommand {
    Append(Box<ReceiptCommitRequest>),
    Flush(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
}
```

`ReceiptCommitActor::start` (line 153) spawns `receipt_commit_actor_loop`
(283), which batches up to `RECEIPT_GROUP_COMMIT_MAX_BATCH = 64`
(line 121) appends per commit. `SqliteReceiptStore::connection()` (490)
returns `self.pool.get()`, that is a reader-pool connection. Pool defaults
are `DEFAULT_READER_POOL_MAX_SIZE = 8` and `DEFAULT_WRITER_POOL_MAX_SIZE = 1`
(`lib.rs:51,57`), and `bootstrap/open.rs` wires
`receipt_commit_actor: ReceiptCommitActor::start(writer_pool)` with
`pool: reader_pool` (open.rs:108-123 and again at 1060-1075). `busy_timeout`
is pinned to 5000ms (`open.rs:8`, enforced 31-35).

Writes that bypass the writer actor and run IMMEDIATE transactions on
`self.connection()` (reader pool):

- `record_session_anchor_record` (`support/store_impl.rs:13-14`)
- `record_request_lineage_record` (`store_impl.rs:40-41`)
- `record_receipt_lineage_statement_record` (`store_impl.rs:70-71`)
- `list_receipt_lineage_statement_links` (`store_impl.rs:93-94`, lazy lineage
  ensure/refresh inside an IMMEDIATE transaction)
- `receipt_lineage_verification` (`store_impl.rs:106-108`, same lazy lineage
  ensure inside an IMMEDIATE transaction)
- `append_child_receipt_record` (`store_impl.rs:114`, connection at 121, full
  validate at 123, full chain verify at 125)
- `append_chio_receipt_consuming_authorization`
  (`receipt_store.rs:587-596`, full validate 589, full chain verify 591)
- `create_next_receipt_checkpoint` (`receipt_store.rs:726-734`, connection at
  731, full validate at 732, then `create_next_receipt_checkpoint_atomic`)
- IOU writes: `SqliteIouEnvelopeStore::open_alongside`
  (`iou_store.rs:65`) calls `Self::open_with_pool(store.pool.clone())`, that
  is the reader pool

The trait append is not atomic with its lineage write:

```rust
// support/store_impl.rs:244
fn append_chio_receipt_returning_seq(
    &self,
    receipt: &ChioReceipt,
) -> Result<Option<u64>, ReceiptStoreError> {
    let connection = self.connection()?;                       // reader pool
    ensure_checkpoint_transparency_guards(&connection)?;       // :249
    verify_latest_checkpoint_integrity(&connection)?;          // :250 full chain
    let seq = SqliteReceiptStore::append_chio_receipt_returning_seq(self, receipt)?; // actor commit
    let mut connection = self.connection()?;                   // :252 THIRD connection
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?; // separate tx
    tx.commit()?;
    Ok(Some(seq))
}
```

Checkpoint creation on the request path, kernel side
(`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs`):

```rust
// receipt_persistence.rs:164
pub(crate) fn record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
    {
        let _receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
            KernelError::Internal("receipt store write lock poisoned".to_string())
        })?;
        if let Some(seq) = self
            .with_receipt_store(|store| Ok(store.append_chio_receipt_returning_seq(receipt)?))?
            .flatten()
        {
            if self.should_checkpoint_after_seq(seq) {          // :179
                self.maybe_trigger_checkpoint_locked(seq)?;     // :180 O(N) UNDER THE LOCK
            }
        }
        self.append_chio_receipt_to_local_log(receipt.clone());
    }
    let _settlement_status = self.run_settlement_observer(receipt);
    Ok(())
}
```

`maybe_trigger_checkpoint_locked` (receipt_persistence.rs:197) loops up to
`CHECKPOINT_CONFLICT_RETRIES = 8` (line 201), each iteration calling
`refresh_checkpoint_counters_from_store` and
`store.create_next_receipt_checkpoint(...)` (210-215), all under the lock.
`record_child_receipts` (`kernel/dispatch.rs:482`) acquires the same lock
once per child receipt in a loop and can checkpoint per iteration (487-500).
`receipt_store_write_lock` is a `std::sync::Mutex<()>`
(`kernel/kernel_struct.rs:2` import, field at `:147`);
`DEFAULT_CHECKPOINT_BATCH_SIZE = 100` (`kernel_struct.rs:121`).

Store-side checkpoint creation duplicates full verification:
`create_next_receipt_checkpoint_atomic` (`checkpoint_validate.rs:393`) runs
`verify_checkpoint_chain_integrity` at line 400, and
`store_kernel_checkpoint_tx` (454) runs it again at 465 (idempotent branch),
473-475 (`validate_checkpoint_against_claim_log` then chain verify), and 536
(post-insert). The builder and predecessor primitives already exist and are
cheap when handed a known predecessor:

```rust
// kernel/checkpoint.rs:777
pub fn build_checkpoint_with_previous(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
    previous_checkpoint: Option<&KernelCheckpoint>,
) -> Result<KernelCheckpoint, CheckpointError>

// kernel/checkpoint.rs:272 -- RFC 8785 canonical JSON body digest
pub fn checkpoint_body_sha256(body: &KernelCheckpointBody) -> Result<String, CheckpointError>

// kernel/checkpoint.rs:881
pub fn validate_checkpoint_predecessor(
    predecessor: &KernelCheckpoint,
    checkpoint: &KernelCheckpoint,
) -> Result<(), CheckpointError>
```

## Design

Three coordinated changes, all in `chio-store-sqlite` plus a small kernel
surface, with the CLI audit promotion carried in rollout step 3. The verified
head is owned exclusively by the single commit actor thread, so it needs no
lock.

### 1. Verified-head cache (closes F22, enables F28)

Add a head owned by the actor loop. It records the last position the actor
has verified so subsequent appends verify only the delta.

```rust
// receipt_store.rs (new, private to the commit actor)
/// Last verified position of the receipt chain. Owned exclusively by the
/// commit-actor thread; never shared, never locked.
#[derive(Clone, Debug, Default)]
struct VerifiedHead {
    /// The newest checkpoint the actor has verified, already parsed and
    /// signature-checked once. `None` before the first checkpoint.
    latest_checkpoint: Option<KernelCheckpoint>,
    /// Row count of `claim_receipt_log_entries` as last verified.
    claim_log_count: u64,
    /// MAX(entry_seq) of `claim_receipt_log_entries` as last verified.
    claim_log_max_seq: u64,
}

impl VerifiedHead {
    fn checkpoint_seq(&self) -> u64 {
        self.latest_checkpoint
            .as_ref()
            .map_or(0, |c| c.body.checkpoint_seq)
    }
    fn checkpointed_entry_seq(&self) -> u64 {
        self.latest_checkpoint
            .as_ref()
            .map_or(0, |c| c.body.batch_end_seq)
    }
}
```

The head is seeded once, at actor start, by running the existing full
verification exactly once (this is the "startup path" for the O(N) check):

```rust
// runs once inside ReceiptCommitActor::start, before serving appends
fn seed_verified_head(
    connection: &Connection,
) -> Result<VerifiedHead, ReceiptStoreError> {
    validate_claim_receipt_log_entries(connection)?;            // full, once
    let latest_checkpoint = verify_checkpoint_chain_integrity(connection)?; // full, once
    let (claim_log_count, claim_log_max_seq) =
        claim_log_count_and_max_seq(connection)?;               // two aggregates
    Ok(VerifiedHead {
        latest_checkpoint,
        claim_log_count,
        claim_log_max_seq,
    })
}
```

If seeding fails the store opens fail-closed: the actor records the error in
`ReceiptCommitWriterHealth.last_error` and rejects appends with
`ReceiptStoreError::Conflict` until `chio receipt audit --repair` clears it.
Because the head is owned by the actor thread, the repair reseed is delivered
as a writer command (change 3): its closure reruns `seed_verified_head` on
the writer connection and, on success, the actor adopts the fresh head and
clears the failed-seed state.

The new append fast path replaces the two O(N) calls with work bounded by the
batch. It runs on the writer connection (see change 3), takes
`&mut VerifiedHead`, and does:

```rust
fn append_receipt_batch(
    connection: &mut SqliteStoreConnection,
    head: &mut VerifiedHead,
    requests: &[ReceiptCommitRequest],
) -> Vec<Result<u64, ReceiptStoreError>> {
    if let Err(error) = ensure_checkpoint_transparency_guards(connection) {
        return receipt_batch_error_results(requests.len(), error);
    }
    // O(1) predecessor check: the persisted latest checkpoint must still
    // match the head we verified. One indexed row read plus a digest compare,
    // not a whole-chain rebuild.
    if let Err(error) = verify_head_against_latest_checkpoint(connection, head) {
        return receipt_batch_error_results(requests.len(), error);
    }
    let tx = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(error) => {
            return receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error));
        }
    };
    let mut results = Vec::with_capacity(requests.len());
    for request in requests {
        match append_chio_receipt_tx(&tx, &request.receipt, &request.raw_json) {
            Ok(seq) => results.push(Ok(seq)),
            Err(error) => return receipt_batch_error_results(requests.len(), error),
        }
    }
    // A duplicate append is idempotent: append_chio_receipt_tx inserts with
    // ON CONFLICT(receipt_id) DO NOTHING (receipt_store.rs:972) and returns
    // the existing claim-log entry_seq for byte-identical duplicates
    // (:992-1011) without adding a projection row. Only entry_seqs beyond the
    // verified head count as new rows; counting every Ok would fire a false
    // Conflict on any idempotent re-append.
    let inserted = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .filter(|seq| **seq > head.claim_log_max_seq)
        .count() as u64;
    // O(batch) projection cross-check over the delta only: the
    // chio_tool_receipts_project_claim_log_entry trigger (bootstrap/open.rs:676;
    // child variant at :711) must have advanced the projection by exactly the
    // rows we inserted. The aggregate is scoped
    // `WHERE entry_seq > head.claim_log_max_seq` so it is an indexed range
    // scan over the new rows; a bare COUNT(*) would scan the whole index and
    // reintroduce O(N).
    let (delta_count, post_max) =
        match claim_log_delta_count_and_max_seq_tx(&tx, head.claim_log_max_seq) {
            Ok(pair) => pair,
            Err(error) => return receipt_batch_error_results(requests.len(), error),
        };
    if delta_count != inserted || post_max < head.claim_log_max_seq {
        return receipt_batch_error_results(
            requests.len(),
            ReceiptStoreError::Conflict(
                "claim receipt log projection drift on append; run `chio receipt audit`".to_string(),
            ),
        );
    }
    match tx.commit() {
        Ok(()) => {
            head.claim_log_count = head.claim_log_count.saturating_add(delta_count);
            head.claim_log_max_seq = post_max;
            results
        }
        Err(error) => receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error)),
    }
}
```

`verify_head_against_latest_checkpoint` reads only the single latest
checkpoint row and compares its identity to `head.latest_checkpoint`:

```rust
fn verify_head_against_latest_checkpoint(
    connection: &Connection,
    head: &VerifiedHead,
) -> Result<(), ReceiptStoreError> {
    let persisted = load_latest_persisted_checkpoint_row(connection)?; // one indexed row
    match (persisted, head.latest_checkpoint.as_ref()) {
        (None, None) => Ok(()),
        (Some(row), Some(cached)) => {
            // Deserialize the body only. parse_persisted_checkpoint_row would
            // run chio_kernel::checkpoint::validate_checkpoint
            // (checkpoint_validate.rs:271), which re-verifies the checkpoint
            // signature; that would put one Ed25519 verify back on every
            // append. The cached head was signature-checked at seed time.
            let persisted_body: KernelCheckpointBody =
                serde_json::from_str(&row.statement_json)?;
            // Compare canonical body digest (RFC 8785) rather than full re-verify.
            let persisted_digest = checkpoint_body_sha256(&persisted_body)
                .map_err(checkpoint_error_to_receipt_store)?;
            let cached_digest = checkpoint_body_sha256(&cached.body)
                .map_err(checkpoint_error_to_receipt_store)?;
            if persisted_digest == cached_digest {
                Ok(())
            } else {
                Err(ReceiptStoreError::Conflict(
                    "latest checkpoint diverged from verified head; run `chio receipt audit`".to_string(),
                ))
            }
        }
        _ => Err(ReceiptStoreError::Conflict(
            "checkpoint presence diverged from verified head; run `chio receipt audit`".to_string(),
        )),
    }
}
```

Per-receipt signature verification is unchanged and stays exactly once, at
ingest: `append_verified_chio_receipt_record` (receipt_store.rs:553) already
calls `ensure_chio_receipt_verified` (:558) before enqueue. The ~2N
re-verifications came only from the full chain rebuild, which the hot path no
longer runs.

Two adjacent callers of the full verification also change. `flush_report`
(receipt_store.rs:736) runs `validate_claim_receipt_log_projection_current`
(:740, defined at :763), the same full projection scan, on every flush; it
switches to the actor's head snapshot so flush cost is also independent of N.
`receipt_checkpoint_status` (receipt_store.rs:667), which runs the full chain
verify at :674, deliberately stays full-fat: it is the operator status and
audit surface that rollout step 3 promotes to `chio receipt audit`.

### 2. Background, single-verification checkpoint creation (closes F28, F07)

Checkpoint construction moves onto the actor thread and uses the cached head
as the predecessor, so it never rebuilds the chain. The kernel stops
building checkpoints on the request path.

Actor-self-triggered: after each append batch commits, the actor checks
whether the head crossed the count threshold and, if so, builds the next
checkpoint in the same writer thread (still off the request path, because the
caller's `append` has already returned durably):

```rust
// inside the actor loop, after a successful append batch
fn maybe_build_checkpoint(
    connection: &mut SqliteStoreConnection,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<(), ReceiptStoreError> {
    if signer.max_batch == 0 {
        return Ok(()); // ADR-0008: batch_size 0 disables checkpointing
    }
    while head.claim_log_max_seq.saturating_sub(head.checkpointed_entry_seq()) >= signer.max_batch {
        let Some(range) = next_checkpoint_range_for_connection(connection, signer.max_batch)? else {
            break;
        };
        let receipt_bytes = load_claim_tree_canonical_bytes_range(connection, range.start_seq, range.end_seq)?
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint_seq = head.checkpoint_seq().checked_add(1).ok_or_else(|| {
            ReceiptStoreError::Conflict("checkpoint_seq overflow".to_string())
        })?;
        // O(batch) Merkle build; predecessor digest comes from the cached head.
        let checkpoint = build_checkpoint_with_previous(
            checkpoint_seq,
            range.start_seq,
            range.end_seq,
            &receipt_bytes,
            &signer.keypair,
            head.latest_checkpoint.as_ref(),
        )
        .map_err(checkpoint_error_to_receipt_store)?;
        insert_checkpoint_incremental(connection, head.latest_checkpoint.as_ref(), &checkpoint)?;
        head.latest_checkpoint = Some(checkpoint);
    }
    Ok(())
}
```

`insert_checkpoint_incremental` is the slimmed replacement for
`store_kernel_checkpoint_tx`. It runs, in one IMMEDIATE transaction:
`validate_checkpoint(&checkpoint)`, `validate_checkpoint_predecessor(head, &checkpoint)`
against the cached head only (not a chain rebuild),
`validate_checkpoint_against_claim_log` for the one new range, the INSERT, and
a single read-back equality check. The redundant
`verify_checkpoint_chain_integrity` calls at `checkpoint_validate.rs:465,
475, 536` are removed. Conflict races (a checkpoint appearing concurrently)
cannot happen once all checkpoint writes go through the single actor, so the
8-round retry loop is retired with the kernel path.

Signer install seam (called once by the kernel after `open`, before serving):

```rust
pub struct BackgroundCheckpointSigner {
    pub keypair: Arc<Keypair>,
    pub max_batch: u64,
}

impl SqliteReceiptStore {
    /// Install the background checkpoint signer. Idempotent per store.
    /// Until called, the store appends without producing checkpoints.
    pub fn enable_background_checkpoints(
        &self,
        signer: BackgroundCheckpointSigner,
    ) -> Result<(), ReceiptStoreError>;
}
```

The actor thread is already running when the kernel calls this, so the signer
crosses into the loop over the existing command channel as a dedicated
`InstallSigner(BackgroundCheckpointSigner)` command (added alongside `Write`
in change 3); no shared state or lock is introduced. Until it arrives the
loop skips `maybe_build_checkpoint`.

Kernel change: `record_chio_receipt` (receipt_persistence.rs:164) keeps only
the append and the local-log mirror inside the critical section and drops
lines 179-181; `record_child_receipts` (dispatch.rs:482) drops lines
496-498. `should_checkpoint_after_seq`, `maybe_trigger_checkpoint_locked`,
and the retry constant are removed. The kernel's
`checkpoint_seq_counter`/`last_checkpoint_seq` reporting fields
(kernel_struct.rs:156,158) are refreshed from a cheap head snapshot (latest
checkpoint seq and checkpointed entry seq) exposed through
`ReceiptCommitWriterHealth`, the same snapshot `flush_report` consumes in
change 1. ADR-0008's count-based,
size-100 trigger semantics are preserved; only the execution site moves from
the request thread under the global lock to the writer thread.

### 3. True single writer (closes F29)

Add one generic writer command so every write runs on the writer connection.
The reader pool becomes strictly read-only.

```rust
type WriterClosure = Box<dyn FnOnce(&mut SqliteStoreConnection) + Send + 'static>;

enum ReceiptCommitCommand {
    Append(Box<ReceiptCommitRequest>),
    Flush(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
    Write(WriterClosure),                       // NEW: generic single-writer job
    InstallSigner(BackgroundCheckpointSigner),  // NEW: change 2 install seam
}

pub(crate) struct WriterHandle {
    sender: mpsc::SyncSender<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
}

impl WriterHandle {
    /// Run one write transaction on the single writer connection and return
    /// its typed result. Fail-closed on saturation or a dead writer.
    pub(crate) fn run_write<T, F>(&self, job: F) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        let (response, result) = mpsc::sync_channel(1);
        let boxed: WriterClosure = Box::new(move |connection| {
            let _ = response.send(job(connection));
        });
        match self.sender.try_send(ReceiptCommitCommand::Write(boxed)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => return Err(receipt_actor_saturated_error()),
            Err(mpsc::TrySendError::Disconnected(_)) => return Err(receipt_actor_unavailable_error()),
        }
        result.recv().map_err(|_| receipt_actor_unavailable_error())?
    }
}
```

The actor loop, on a `Write` command, first commits any pending append batch
(to preserve write ordering), then runs the closure on the writer
connection. After the closure returns, the actor resynchronizes the verified
head on the same connection: one indexed delta aggregate over
`entry_seq > head.claim_log_max_seq` (writer-routed child receipts and
consuming-authorization appends insert claim-log rows through the projection
triggers) and one latest-checkpoint row read (the manual
`create_next_receipt_checkpoint` path inserts checkpoints). Without this
resync, the next append's projection cross-check would fire a false
`Conflict` after any writer-routed insert. The resync observes only what the
writer connection just committed plus any out-of-band drift, and the next
append's predecessor-digest check still bounds the latter. Every method that
currently opens an IMMEDIATE transaction on
`self.connection()` is rewritten to `self.writer.run_write(|conn| { ... })`:
`record_session_anchor_record`, `record_request_lineage_record`,
`record_receipt_lineage_statement_record`,
`append_chio_receipt_consuming_authorization`,
`append_child_receipt_record`, and `create_next_receipt_checkpoint` (now the
audit-only manual path). `list_receipt_lineage_statement_links`
(store_impl.rs:93-94) and `receipt_lineage_verification` (store_impl.rs:106-108)
are not read-only despite their names: both lazily ensure lineage statements
inside an IMMEDIATE transaction, so they route through `run_write` as well.
Genuinely read-only helpers (status, health, and receipt lookup queries) keep
`self.pool` (reader pool). `self.connection()` is narrowed to reads and gains
a doc note that writes must not use it.

Trait-append atomicity: fold the lineage statement into the same writer
transaction as the receipt insert so `append_chio_receipt_returning_seq`
(store_impl.rs:244) can never leave receipt-without-lineage state:

```rust
fn append_chio_receipt_returning_seq(
    &self,
    receipt: &ChioReceipt,
) -> Result<Option<u64>, ReceiptStoreError> {
    ensure_chio_receipt_verified(receipt)?; // signature check once, before enqueue
    let receipt = receipt.clone();
    // RFC 8785 canonical JSON, the same encoding the consuming-authorization
    // path already produces (receipt_store.rs:582-586).
    let raw_json = canonical_json_bytes(&receipt)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    let raw_json = String::from_utf8(raw_json).map_err(|error| {
        ReceiptStoreError::Canonical(format!(
            "canonical receipt bytes are not UTF-8: {error}"
        ))
    })?;
    self.writer.run_write(move |connection| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let seq = append_chio_receipt_tx(&tx, &receipt, &raw_json)?;
        ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
        tx.commit()?;
        Ok(Some(seq))
    })
}
```

IOU store: `SqliteIouEnvelopeStore::open_alongside` (iou_store.rs:65) takes
the shared `WriterHandle` instead of cloning `store.pool`, and its writes go
through `run_write`. It keeps a reader-pool clone for its read queries only.

### Error taxonomy (typed, fail-closed)

No new `ReceiptStoreError` variants are required; the existing enum
(`chio-kernel/src/receipt_store.rs:152`) already carries `Conflict(String)`,
`Pool(String)`, `Timeout { operation, timeout_ms }`, `Sqlite`, `Canonical`,
and `NotFound`. Mapping:

- verified-head divergence (append predecessor or projection cross-check
  fails): `Conflict`, deny the batch, message points to `chio receipt audit`.
- writer saturated / disconnected: `Pool` via `run_write` (fail-closed for
  new writes, matching ADR-0013 queue-saturation semantics).
- seeding failure at open: recorded in `ReceiptCommitWriterHealth.last_error`;
  every append returns `Conflict` until audit-repair clears it.

Every proposed function returns `Result` and uses `?` or explicit `match`;
none use `.unwrap()` or `.expect()`, satisfying the workspace clippy denies.

### Cost model

Per append batch (batch size b, history N): current work is
O(N) rows scanned + O(N/b) Merkle rebuilds + ~2N Ed25519 verifications.
Proposed work is O(b) inserts + O(1) latest-checkpoint row read + one digest
compare + one indexed delta aggregate (`COUNT`/`MAX` scoped to
`entry_seq > head.claim_log_max_seq`, so O(b) not O(N); an unscoped
`COUNT(*)` would scan the whole index), independent of N. Per
checkpoint: current is O(N) (full chain rebuild, executed 2-3 times);
proposed is O(b) (one Merkle tree of b leaves plus one signature), off the
request path. At N = 1M, b = 100 the per-append verification count drops from
~2M signatures to 0 on the hot path.

## Wire, schema, and receipt impact

None. `KernelCheckpoint`, its canonical body, `previous_checkpoint_sha256`
linkage, receipt kinds, and all on-disk schemas are unchanged. Checkpoints
are still built by `build_checkpoint_with_previous` and digested with
`checkpoint_body_sha256` over RFC 8785 canonical JSON, so existing checkpoints
and inclusion proofs remain valid. The verified head is in-memory only and is
reconstructed deterministically at startup; it is never serialized.

## Migration and compatibility

- Backward compatible on disk. An existing database opens, seeds the head via
  one full verification, and then runs incrementally. No data migration.
- Staged rollout behind a store construction flag
  `SqliteReceiptStore` gains `incremental_verification: bool` (default
  `true`); when `false` it keeps the current per-append full verification so
  operators can A/B a suspect database. The flag is read-only after open.
- Single-writer routing lands first and is inert with respect to correctness
  (it only changes which connection executes a write), so it can ship in a
  separate commit ahead of the verification change.
- Background checkpointing is gated by `enable_background_checkpoints`; until
  the kernel calls it the store behaves as today minus request-path
  checkpoint work. ADR-0008 `checkpoint_batch_size = 0` still disables
  checkpointing (early return in `maybe_build_checkpoint`).
- ADR-0013 unchanged: the actor `append` still blocks the caller until the
  batch commits, so a mediated Allow is returned only after the receipt is
  durable. Only checkpoint construction becomes asynchronous, and a checkpoint
  is a Merkle commitment over already-durable, already-signed receipts, so
  deferring it does not weaken receipt durability.

## Test and verification plan

Tie into the wave-3 load-chaos program and the formal-methods plan.

- Unit: `append_receipt_batch` incremental path inserts and updates the head;
  `verify_head_against_latest_checkpoint` accepts a matching head and rejects
  a tampered latest checkpoint (`Conflict`); `maybe_build_checkpoint` builds
  exactly one checkpoint per crossed threshold and links
  `previous_checkpoint_sha256` to the head.
- Property (proptest): for any interleaving of appends and checkpoint
  thresholds, the incremental head after replay equals the value
  `seed_verified_head` computes by full verification. Name:
  `prop_incremental_head_matches_full_audit`.
- Tamper / fail-closed: mutate a persisted receipt or checkpoint row out of
  band, then append; the next batch must fail with `Conflict` and
  `chio receipt audit` must report the exact divergent seq. Name:
  `append_denies_when_head_diverges`.
- Atomicity: inject a failure between receipt insert and lineage insert; assert
  no receipt-without-lineage row survives (folded transaction rolls back).
  Name: `receipt_and_lineage_commit_atomically`.
- loom: model the actor command channel with concurrent `Append`, `Write`,
  and `Flush`; assert single-writer serialization and no lost `inflight`
  accounting (the existing pre-send increment invariant at receipt_store.rs:177
  must hold for `Write` too).
- Soak: 10M appends at batch 100 with periodic checkpoints; assert per-append
  p99 latency is flat across the run (no growth with N) and RSS is bounded.
  Name: `soak_flat_append_latency_10m`.
- Chaos: concurrent multi-tenant writers plus a slow reader; assert zero
  `SQLITE_BUSY` write failures now that all writes serialize on one
  connection. Name: `chaos_no_busy_under_multiwriter`.
- Benchmark: microbench append at N in {1e3, 1e5, 1e6}; assert append cost is
  within a constant factor across N (proves O(1) per append).

## Acceptance criteria

- Per-append work is independent of total history: the append microbench at
  N = 1e6 is within 2x of N = 1e3.
- No `validate_claim_receipt_log_entries` or `verify_checkpoint_chain_integrity`
  call remains on the append, flush, or checkpoint hot path; both survive only
  in the operator surfaces (`chio receipt audit` /
  `receipt_checkpoint_status`) and the one-time `seed_verified_head` at open.
- `record_chio_receipt` and `record_child_receipts` hold
  `receipt_store_write_lock` across no checkpoint construction; checkpoints are
  produced by the writer actor.
- Every write transaction executes on the writer connection; a test asserts
  the reader pool never begins a write transaction.
- Receipt and lineage commit in one transaction; the atomicity test passes.
- Out-of-band tampering is caught fail-closed on the next append and localized
  by `chio receipt audit`.
- ADR-0013 durability tests still pass unchanged.

## Risks and alternatives

- Risk: the delta count/max cross-check is weaker than full set-equality and
  could miss an equal-count substitution. Mitigation: the per-append signature
  check at ingest and the predecessor-digest check bound what an attacker can
  substitute without detection, and `chio receipt audit` (full set-equality
  plus full chain) runs on a schedule and at every restart. This is the
  intended trade: cheap continuous invariant plus periodic deep audit.
- Risk: a poisoned or lagging head stalls all appends (fail-closed by design).
  Mitigation: `chio receipt audit --repair` re-seeds the head; health surfaces
  the stall immediately via `last_error`.
- Risk: background checkpointing means a crash can lose the most recent
  uncheckpointed batch's Merkle commitment. This is already true under
  ADR-0008 (count-based, partial final batch) and does not affect receipt
  durability; the next start re-derives coverage from the durable receipts.
- Alternative rejected: keep checkpointing synchronous but skip the full chain
  rebuild. This fixes F22/F28 CPU but leaves the O(N) verification coupled to
  the request path and the global lock (F07), so tail latency still depends on
  chain size. Rejected in favor of moving construction to the writer thread.
- Alternative rejected: convert `receipt_store_write_lock` to a tokio async
  mutex. It does not remove the O(N) work and still blocks worker threads on
  sync SQLite I/O. Out of scope; this RFC removes the O(N) work from the
  critical section, which is the dominant harm.
- Throughput note: routing lineage/anchor/IOU writes through the single writer
  serializes them with receipt appends. Because each is a short IMMEDIATE
  transaction and they previously contended for the same SQLite write lock
  anyway (just via the reader pool), measured throughput should improve, not
  regress, once `SQLITE_BUSY` retries disappear.

## Rollout and sequencing

1. Single-writer routing and the folded receipt+lineage transaction (F29).
   Correctness-preserving, no verification change; ship first.
2. Verified-head cache and incremental append fast path (F22), behind
   `incremental_verification` default `true` with the full-path fallback.
3. `chio receipt audit` CLI: promote the existing full verification. The verb
   already exists as `cmd_receipt_checkpoint_verify`
   (`crates/products/chio-cli/src/cli/trust/receipt/health.rs:124`, which calls
   `receipt_checkpoint_status(Some(1))` and thus the full chain path); rename
   and extend it to `audit`/`audit --repair` that runs
   `validate_claim_receipt_log_entries` plus `verify_checkpoint_chain_integrity`
   and re-seeds the head.
4. Background checkpointing via `enable_background_checkpoints`, with the kernel
   dropping request-path checkpoint construction (F28, F07).

This RFC is a dependency of RFC-0003, RFC-0004, and RFC-0007; those build on a
receipt store whose append cost is bounded and whose writer discipline is
single-threaded, so RFC-0006 must land first.
