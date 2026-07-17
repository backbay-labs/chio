# RFC-0003: Durable dispatch-intent journal: closing the effect-before-receipt crash window

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0013 (async receipt durability), ADR-0008 (checkpoint trigger strategy)
- Depends on: RFC-0006 (storage hot path: bounded append cost and single-writer
  discipline for the store this journal rides on; RFC-0006 sequences itself before
  this RFC). Related: RFC-0009 (alert routing for dead-letter incidents), RFC-0013
  (money-path idempotency contract)
- Closes findings: F04, F31. Provides groundwork for F70 only, which is owned
  and closed by RFC-0013 (payment journal and idempotent adapter contract), not
  this RFC (see ./README.md and the wave-3 readiness review)

## Summary

Today a mediated tool call executes its side effect (and, on the money path, moves
funds at `authorize`) strictly before the kernel signs and durably persists the
receipt. A crash, OOM kill, or power loss anywhere in that window leaves an
externally visible effect with no receipt in the append-only log, and recovery has
nothing to reconcile against: the Merkle-committed log verifies clean while missing
an action. This RFC adds a durable dispatch-intent journal. Before a side-effecting
or monetary call dispatches, the kernel writes a small intent row through the
`ReceiptCommitActor` group-commit path and blocks on its durable commit. The receipt
append later consumes that intent row in the same writer transaction as the receipt
insert, so the two either both commit or both do not. Orphaned intents surviving a
restart are reconciled at boot into explicit "outcome-unknown" incidents (and, for
monetary intents, a rail-side query), turning a silent audit hole into a loud,
recoverable operator signal. Read-only calls pay nothing: intent writes are gated on
side-effect class.

## Motivation

The failure is a durability gap in the core product guarantee ("every mediated side
effect has a receipt"), grounded in F04, F31, and F70, and read against the
Ubicloud "PostgreSQL and the OOM Killer" lens: when a component dies mid-operation
you must know the blast radius and be able to recover, and internal accounting must
be trustworthy or loudly broken. Here the accounting is silently broken.

Blast radius:

- Trigger: kernel process death (OOM kill, crash, power loss) in the window between
  the tool server returning a side effect (or the rail moving money) and
  `record_chio_receipt` committing the signed receipt.
- Effect: the effect happened; no receipt exists anywhere. The in-memory local-log
  copy either died with the process or was never written, because on a store-append
  failure the local-log append is skipped (the error propagates first). Recovery has
  no per-call intent record to detect the gap.
- Who is impacted: auditors and dispute resolution (the log verifies clean while
  missing an action); on the money path (F70) the payer was charged with no attested
  record and no local copy of the rail `authorization_id`, so reconciliation requires
  manual rail-side statement matching.

F03 (memory-growth-induced OOM) makes the crash trigger routine rather than rare, so
this is not a tail concern. The existing `PostAdmissionDropGuard`
(`crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs:19`) covers only
in-process future-drop and cancellation; it is memory-only and does not survive
process death, so it cannot close this window.

## Current behavior (verified 2026-07-04)

Ordering in the async evaluation path
(`crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`):

1. Pre-dispatch readiness gates run at lines 219-250
   (`ensure_federated_receipt_persistence_ready`, `ensure_receipt_persistence_ready`).
   Both are configuration-presence checks only. Verified in
   `crates/kernel/chio-kernel/src/kernel/construction.rs:244-251`:

   ```rust
   pub(crate) fn ensure_receipt_persistence_ready(&self) -> Result<(), KernelError> {
       if self.receipt_store.is_some() || self.config.allow_ephemeral_receipt_log {
           return Ok(());
       }
       Err(KernelError::Internal(
           "durable receipt persistence unavailable: no receipt store configured".to_string(),
       ))
   }
   ```

   Neither gate consults writer counters, queue depth, `last_error`, or thread
   liveness, so a saturated queue or wedged writer passes.

2. Money moves at `authorize_payment_if_needed`
   (`async_evaluation_core.rs:469-492`), which is before dispatch. For the in-tree
   prepaid X402 adapter the real external HTTP call is in `authorize`
   (`crates/kernel/chio-kernel/src/payment.rs:287-310`) and `capture` is a local
   no-op returning `Settled` (`payment.rs:312-329`), so for prepaid rails funds
   move at pre-dispatch authorize. Generic adapters move funds at `capture`
   (`crates/kernel/chio-kernel/src/kernel/validation.rs:1012-1021`), still before
   the receipt persists.

3. The tool side effect executes at `async_evaluation_core.rs:525-527`
   (`dispatch_tool_call_with_cost_after_nonce_check`), guarded only by the
   memory-only `PostAdmissionDropGuard` (lines 513-529).

4. The receipt is built, signed, and only then persisted, strictly afterward
   (`crates/kernel/chio-kernel/src/kernel/responses/allow_responses.rs:57-72`):
   `build_and_sign_receipt` at 57-70, then `record_chio_receipt_with_federation` at
   72.

5. `record_chio_receipt` takes the kernel-wide write lock, appends durably, and only
   on success writes the in-memory local log
   (`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:164-187`):

   ```rust
   pub(crate) fn record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
       {
           let _receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
               KernelError::Internal("receipt store write lock poisoned".to_string())
           })?;
           if let Some(seq) = self
               .with_receipt_store(|store| Ok(store.append_chio_receipt_returning_seq(receipt)?))?
               .flatten()
           {
               if self.should_checkpoint_after_seq(seq) {
                   self.maybe_trigger_checkpoint_locked(seq)?;
               }
           }
           self.append_chio_receipt_to_local_log(receipt.clone());
       }
       let _settlement_status = self.run_settlement_observer(receipt);
       Ok(())
   }
   ```

   The durable append is `SqliteReceiptStore::append_verified_chio_receipt_record`
   (`crates/platform/chio-store-sqlite/src/receipt_store.rs:553-562`), which hands a
   single `Append` command to the `ReceiptCommitActor`
   (`receipt_store.rs:161-200`). The actor group-commits a batch inside one
   `TransactionBehavior::Immediate` transaction in `append_receipt_batch`
   (`receipt_store.rs:376-415`), inserting each row via `append_chio_receipt_tx`
   (`receipt_store.rs:939`), whose statement is:

   ```sql
   INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, subject_key,
       issuer_key, grant_index, tool_server, tool_name, decision_kind, policy_hash,
       content_hash, tenant_id, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
   ON CONFLICT(receipt_id) DO NOTHING RETURNING seq
   ```

There is no dispatch-intent or write-ahead-intent record anywhere in the store API:
a grep for `intent` in `receipt_store.rs` returns nothing. The only per-call durable
precedent that does the "consume in the same transaction as the receipt insert" move
is `append_chio_receipt_consuming_authorization`
(`crates/platform/chio-store-sqlite/src/receipt_store.rs:564-597`), which runs
`consume_authorization_receipt_tx` (`receipt_store.rs:1017`) and `append_chio_receipt_tx`
inside one `Immediate` transaction. This RFC generalizes exactly that pattern.

Group-commit constants (`receipt_store.rs:121-123`):
`RECEIPT_GROUP_COMMIT_MAX_BATCH = 64`, `RECEIPT_GROUP_COMMIT_FLUSH_DELAY = 500us`,
`RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY = 64 * 16 = 1024`.

Health surface today (`receipt_store.rs:614-631`): `healthy = status.healthy &&
writer_counters().last_error.is_none()`. `ReceiptStoreHealthReport`
(`crates/kernel/chio-kernel/src/receipt_store.rs:100-117`) has no notion of an
in-flight or orphaned call. Its only external consumer is the CLI `trust receipt
health` command (`crates/products/chio-cli/src/cli/trust/receipt/health.rs:60-73`),
which opens its own store via `open_existing` (`health.rs:43`) and therefore cannot
observe the serving kernel's writer state.

Parameter hashing is already canonical (RFC 8785) via
`ToolCallAction::from_parameters`
(`crates/core/chio-core-types/src/receipt/decision.rs:44-51`):
`sha256_hex(canonical_json_bytes(&parameters))`. The intent row reuses this exact
hash so the intent and the eventual receipt bind to the same call.

## Design

### Overview and invariant

Introduce a durable, non-audit operational journal (`chio_dispatch_intents`) that
sits beside the Merkle-committed `chio_tool_receipts` table. The invariant:

> For any side-effecting or monetary mediated call, a durable intent row exists on
> disk before the effect is caused, and it is removed in the same transaction that
> commits the receipt. Therefore, after any crash, `receipt(request_id) XOR
> open_intent(request_id)` holds: either the receipt is durable, or an intent proves
> an effect may have occurred without one.

Intents are operational records, not receipts. They are never signed, never added to
`chio_tool_receipts`, and never advance the checkpoint sequence, so ADR-0008's
count-based checkpoint semantics and the Merkle tree are untouched.

### Schema (new table)

Added in `crates/platform/chio-store-sqlite/src/receipt_store/bootstrap/open.rs`
alongside the `chio_tool_receipts` DDL (currently at `open.rs:131-158`):

```sql
CREATE TABLE IF NOT EXISTS chio_dispatch_intents (
    request_id            TEXT PRIMARY KEY,
    capability_id         TEXT NOT NULL,
    tool_server           TEXT NOT NULL,
    tool_name             TEXT NOT NULL,
    parameter_hash        TEXT NOT NULL,
    side_effect_class     TEXT NOT NULL,          -- 'side_effecting' | 'monetary'
    monetary              INTEGER NOT NULL,        -- 0 | 1
    rail                  TEXT,                    -- adapter/rail id, known pre-authorize
    rail_authorization_id TEXT,                    -- attached post-authorize (money path)
    tenant_id             TEXT,
    created_at_unix_ms    INTEGER NOT NULL,
    state                 TEXT NOT NULL DEFAULT 'open', -- 'open' | 'dead_letter'
    resolution_detail     TEXT                     -- reconciler outcome annotation
);

CREATE INDEX IF NOT EXISTS idx_chio_dispatch_intents_state
    ON chio_dispatch_intents(state);
```

`request_id` is the primary key: at most one open intent per request. A second write
for the same `request_id` (a retry that reused the id) collides and is rejected
fail-closed rather than duplicating an effect record. The row carries no arguments,
only `parameter_hash`, so it holds no additional sensitive payload beyond what the
receipt already commits.

### New Rust types

In `crates/kernel/chio-kernel/src/receipt_store.rs`, beside
`AuthorizationReceiptConsumption` (currently at lines 133-149):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    /// Pure/read-only: no durable intent is written; TTFRH is unchanged.
    ReadOnly,
    /// Externally visible effect (file write, message send, non-monetary tool).
    SideEffecting,
    /// Moves funds on a payment rail; carries a rail reference.
    Monetary,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchIntentRecord {
    pub request_id: String,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub parameter_hash: String,
    pub side_effect_class: SideEffectClass,
    pub monetary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail_authorization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub created_at_unix_ms: u64,
}

/// Key used to consume an intent in the same transaction as the receipt append.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchIntentKey {
    pub request_id: String,
    /// Must equal the receipt's action.parameter_hash; a mismatch fails closed.
    pub parameter_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}
```

### Store trait additions

In the `ReceiptStore` trait
(`crates/kernel/chio-kernel/src/receipt_store.rs:187`), add two defaulted methods so
non-SQLite stores remain compilable and fail closed if used on a side-effecting path:

```rust
fn record_dispatch_intent(
    &self,
    _intent: &DispatchIntentRecord,
) -> Result<(), ReceiptStoreError> {
    Err(ReceiptStoreError::Conflict(
        "durable dispatch-intent journal is not supported by this receipt store".to_string(),
    ))
}

fn append_chio_receipt_consuming_intent(
    &self,
    _receipt: &ChioReceipt,
    _intent: &DispatchIntentKey,
) -> Result<Option<u64>, ReceiptStoreError> {
    Err(ReceiptStoreError::Conflict(
        "durable dispatch-intent consumption is not supported by this receipt store".to_string(),
    ))
}
```

The SQLite implementations live next to
`append_chio_receipt_consuming_authorization`
(`crates/platform/chio-store-sqlite/src/receipt_store.rs:564-597`) and, like
that method, run inside their own `Immediate` transaction, but both route
through the `ReceiptCommitActor`'s single writer connection as jobs on the
existing generic `Write` command rather than opening a connection directly:
`record_dispatch_intent` queues a metadata-only `Write` job
(`WriterHandle::run_write`, `receipt_store.rs:798-804`), and
`append_chio_receipt_consuming_intent` queues a receipt-appending `Write` job
(`WriterHandle::run_write_receipt`, `receipt_store.rs:810-816`) that performs
the consume and the receipt insert together. This keeps every journal write on
the single writer thread that RFC-0006 establishes.

### Dispatch-intent writer jobs

As shipped, this does not extend `ReceiptCommitCommand`
(`crates/platform/chio-store-sqlite/src/receipt_store.rs:482-521`) with an
`Intent` variant, and `ReceiptCommitRequest` (`receipt_store.rs:448-456`) gains
no `consume_intent` field; both are unchanged from RFC-0006 (`Append`, `Flush`,
`Write { job, appends_receipts }`, `ReseedHead`, `InstallSigner`, `Rotate`,
`RetentionRepair`). A heterogeneous Intent+Append group-commit batch was the
original design sketch, but every dispatch-intent operation instead rides the
existing `Write` command as its own independent job on the single writer, each
inside its own transaction:

- **Insert** (`record_dispatch_intent`, `receipt_store.rs:3276-3284`): a
  metadata-only `Write` job (`dispatch_intent_insert_job`,
  `receipt_store/support/dispatch_intent.rs:77-88`) that opens its own
  `TransactionBehavior::Immediate` transaction, runs `insert_dispatch_intent_tx`
  (`INSERT ... ON CONFLICT(COALESCE(tenant_id, ''), request_id) DO NOTHING`,
  mapping `changed == 0` to `ReceiptStoreError::Conflict`, fail-closed; the
  existing row is left untouched), and commits.
- **Consume** (`append_chio_receipt_consuming_intent`,
  `receipt_store.rs:3354-3361`): a receipt-appending `Write` job whose closure
  (`receipt_store.rs:3413-3422`) opens its own `Immediate` transaction, runs
  `finalize_dispatch_intent_tx` (a tenant- and parameter-hash-guarded `DELETE`)
  then `append_chio_receipt_tx` then the lineage statement, and commits once.
  A `parameter_hash` or tenant mismatch is a `Conflict` raised from inside the
  transaction and rolls back that job's commit, so the receipt insert and the
  intent delete either both land or neither does.
- **Rail-ref attach, clear, timeout sweep, dead-letter resolve, reconcile**:
  each is its own `Write` (or bounded/detached `Write`) job with its own
  transaction, guarded on the row's current `state` so a job that arrives
  after the row already changed state is a no-op `NotFound` rather than a
  corrupting write (`attach_dispatch_intent_rail_ref`,
  `clear_dispatch_intent`, `resolve_dead_letter_dispatch_intent`,
  `receipt_store.rs:3429`, `3461`, `4008`).

Because each of these is queued and run as its own job, relative ordering
between two operations on the same request comes from the writer's FIFO
queue, not from sharing a batch or a transaction. For example, the
timeout-path compensating sweep
(`record_dispatch_intent_with_timeout`, `receipt_store.rs:3299-3348`) is
enqueued strictly after the insert job it sweeps, so it always observes that
insert's outcome. There is no heterogeneous Intent+Append batch anywhere in
the store: cross-operation partial commit is not merely guarded against, it
is structurally impossible, because no two distinct dispatch-intent
operations, or an intent operation and an unrelated receipt append, ever
share a transaction. This is simpler than the group-commit batch originally
sketched here and gives the same same-transaction-consume guarantee, since
the only two statements that must be atomic together (the intent DELETE and
the receipt INSERT) already share one job's one transaction.

Durability of the pre-dispatch intent write: `record_dispatch_intent` blocks
on the `Write` job's response channel exactly as a batched `Append` does, and
the response is sent only after that job's `tx.commit()` returns, so the
caller observes a durable (WAL-fsynced) commit before it proceeds to dispatch.
Saturation and a disconnected/dead writer are surfaced through the same typed
`ReceiptStoreError` variants (`Pool`, `Timeout`, `Sqlite`) every other writer
job already uses.

### Kernel control-flow changes

In `async_evaluation_core.rs`, insert one step after the budget increment
(currently at line 252) and before `authorize_payment_if_needed` (line 469), so the
intent is durable before the earliest possible effect (prepaid authorize at 469, or
tool dispatch at 525-527):

```rust
// Fail-closed: for side-effecting or monetary calls, write and durably commit a
// dispatch-intent row BEFORE any external effect. On failure we deny here, before
// the effect, converting the old post-effect ReceiptPersistence error into a safe
// pre-effect deny. The budget hold (check_and_increment_budget, line 252) is
// already applied at this point, so a persistence failure must reverse it before
// returning, exactly as the other pre-dispatch abort arms do; a bare `?` here
// would leak the hold on a denied-before-dispatch call.
let dispatch_intent = match self.record_dispatch_intent_if_side_effecting(
    request, cap, matched_grant_index,
) {
    Ok(Some(handle)) => Some(handle),
    Ok(None) => None, // read-only class: no journal write, TTFRH unchanged
    Err(error) => {
        // Reverse the pre-execution hold through the same charge-gated primitive
        // the authorize/admission abort arms use (RFC-0002). payment auth is None
        // (authorize runs later, line 469); a non-monetary side-effecting call
        // holds no charge, so this is a no-op. A reversal error is recorded but
        // never masks the deny.
        if let Err(unwind_error) = self.unwind_aborted_monetary_invocation(
            request, cap, budget_mutation.charge_result(), None,
        ) {
            tracing::error!(
                error = %unwind_error,
                "failed to reverse budget hold after dispatch-intent persistence failure"
            );
        }
        return Err(error);
    }
};
```

`record_dispatch_intent_if_side_effecting` (new, on the kernel) computes the
`SideEffectClass` from the tool manifest annotation and `has_monetary`
(`budget_mutation.charge_result().is_some()`, verified at
`async_evaluation_core.rs:512`). The read-only signal is the existing
`ToolAnnotations::read_only` flag (`crates/core/chio-core-types/src/manifest.rs:126`;
`read_only == true` maps to `SideEffectClass::ReadOnly`); `has_monetary` promotes to
`Monetary`, and everything else is `SideEffecting`. Because `read_only` defaults to
`false` (`#[serde(default)]`), an unannotated or unknown tool fails safe: it is
treated as side-effecting and gets a durable intent, never silently skipped. The
sibling `ToolAnnotations::idempotent` flag is the natural input a reconciler consults
before ever returning `SafeToReplay`. Given a class, the method:

- Returns `Ok(None)` for `ReadOnly` (no write, no latency cost).
- Otherwise builds a `DispatchIntentRecord` whose `parameter_hash` comes from
  `ToolCallAction::from_parameters(request.arguments.clone())`
  (`decision.rs:44`), sets `rail` to the configured adapter id for monetary calls
  (leaving `rail_authorization_id = None` until authorize returns), and calls
  `store.record_dispatch_intent(&intent)`. Any error maps to a new fail-closed
  variant, reverses the already-applied pre-execution budget hold (routed through
  `unwind_aborted_monetary_invocation`, the same charge-gated reversal the
  authorize and admission abort arms use, so no hold leaks), and denies before
  dispatch.

Trust posture of the read-only signal: for a tool reached through the MCP adapter
(`crates/protocol/chio-mcp-adapter/src/server.rs`, `AdaptedMcpServer::tool_is_read_only`),
the read-only exemption bottoms out in the upstream MCP server's own
`readOnlyHint` tool annotation, captured into the manifest once at adapt time
(`crates/protocol/chio-mcp-adapter/src/manifest.rs`, `infer_has_side_effects`), not
re-verified per call. The MCP spec treats tool annotations as untrusted hints from
the server describing itself, so a lying or compromised upstream server can mark
its own side-effecting tools `readOnlyHint: true` and exempt them from the journal's
crash-window audit net; policy evaluation, guards, and receipt issuance are
unaffected; only the pre-dispatch durable intent write is skipped. The parsing is
conservative in the operator's favor, not the server's: a malformed hint or an
explicit `destructiveHint: true` overrides a `readOnlyHint: true` and the tool
still journals (`McpToolSafetyHints::has_side_effects`); only a clean, present
`readOnlyHint: true` with no destructive hint earns the exemption.
`DispatchIntentJournalMode::All` is the operator override for a deployment that
does not trust its upstream servers' self-reported hints.

Money path (F70, extended by RFC-0013): after `authorize_payment_if_needed`
(line 469) returns a `PaymentAuthorization`, attach its `authorization_id` to the
open intent via `store.attach_dispatch_intent_rail_ref(request_id, authorization_id)`
(routed through the actor as `DispatchIntentOp::AttachRailRef`). This is
best-effort-durable: even if it fails, the open intent (with `rail` set) already
proves a monetary attempt, and boot reconciliation queries the rail. The full
generic replay-idempotency contract on the `PaymentAdapter` trait
(`crates/kernel/chio-kernel/src/payment.rs:150-181`, which today requires no
idempotency) is specified in RFC-0013, not here.

Consume at receipt time: `record_chio_receipt`
(`receipt_persistence.rs:164-187`) gains a sibling that, when the request carried an
intent, calls `store.append_chio_receipt_consuming_intent(receipt, &key)` instead of
`append_chio_receipt_returning_seq`. Note that `ChioReceipt`
(`crates/core/chio-core-types/src/receipt/body.rs:35-102`) has no `request_id`
field: its `id` is content-addressed and its only call-binding fields are
`capability_id`, `tool_server`, `tool_name`, `action`, and `tenant_id`. The
`DispatchIntentKey` therefore cannot be reconstructed from the receipt alone. Its
`parameter_hash` and `tenant_id` are taken from `receipt.action.parameter_hash` and
`receipt.tenant_id`, but its `request_id` must be threaded forward from the
pre-dispatch dispatch-intent handle (the `dispatch_intent` value produced by
`record_dispatch_intent_if_side_effecting` and carried on the request), not read off
the receipt. Concretely, the sibling method takes both the `&ChioReceipt` and the
already-known `request_id` (or the full `DispatchIntentKey`), so the plumbing from
`async_evaluation_core` through `allow_responses.rs:72`
(`record_chio_receipt_with_federation`) into `record_chio_receipt` must carry the
handle; the receipt is not a sufficient source. The `parameter_hash` binding still
proves the consumed intent matches the exact call the receipt attests. Placing the
consume decision at the `record_chio_receipt` level is deliberate: post-dispatch
deny receipts and terminal records funnel through the same sink
(`record_chio_receipt_with_federation` is also called from `deny_responses.rs:97`
and `terminal_responses.rs:48,108`), so whichever receipt kind a journaled call
ends in, committing that receipt consumes the intent, and an effecting call that
ends in a post-dispatch deny does not leave a false orphan behind. The existing
lock scope, checkpoint trigger (`should_checkpoint_after_seq`,
`receipt_persistence.rs:189-195`), and local-log append are preserved; the only
change is which store method runs under the lock. Unlike the return type of
`append_chio_receipt_consuming_authorization` (which returns `Result<(), _>` and
cannot advance the checkpoint), `append_chio_receipt_consuming_intent` returns
`Result<Option<u64>, ReceiptStoreError>` precisely so the returned `seq` still drives
`should_checkpoint_after_seq`.

### Boot-time reconciliation

At kernel startup, after the store opens and before serving, run
`store.reconcile_dispatch_intents(reconciler)` (invoked from kernel construction,
immediately after the receipt store is opened and before the kernel accepts
requests). It selects `WHERE state = 'open'` and, per row:

- Defensive receipt cross-check: receipts carry no `request_id` (see above), so an
  exact lookup is impossible. If a receipt matching the intent's call-binding tuple
  (`capability_id`, `tool_server`, `tool_name`, `action.parameter_hash`,
  `tenant_id`, timestamp at or after `created_at_unix_ms`) exists, the effect is
  very likely already attested; the same-tx consume should preclude this state. The
  reconciler still dead-letters the intent (fail-closed: a heuristic match never
  silently deletes evidence) and records the probable receipt id in
  `resolution_detail` so the operator can close it in one look.
- Otherwise the intent is an orphan: an effect may have occurred with no receipt.
  The kernel cannot safely re-execute a side effect, so the default action is
  dead-letter, not blind replay. It sets `state = 'dead_letter'` and writes the
  reconciler's outcome into `resolution_detail`. The dead-letter row itself is the
  durable, operator-visible incident record: it is counted in
  `ReceiptStoreHealthReport`, flips `healthy` to false, and is visible to the CLI
  `trust receipt health` command; alert routing for a nonzero count rides the
  RFC-0009 observability and alerting wiring.
- For a monetary orphan with `rail` (and possibly `rail_authorization_id`) set, the
  reconciler additionally queries the rail via the adapter to determine whether funds
  actually moved (RFC-0013 supplies the idempotent query/reconcile contract), and
  annotates the incident with the outcome.
- Replay is permitted only for operations the reconciler proves idempotent and
  non-side-effecting; the default posture treats every orphan as dead-letter.

```rust
pub trait DispatchIntentReconciler: Send + Sync {
    /// Decide how to resolve an orphaned intent surviving a restart.
    fn resolve(
        &self,
        intent: &DispatchIntentRecord,
    ) -> Result<DispatchIntentResolution, ReceiptStoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchIntentResolution {
    /// Effect could not be confirmed; record an outcome-unknown incident.
    DeadLetter { detail: String },
    /// Reconciler proved the effect never occurred and it is safe to retry.
    SafeToReplay,
    /// Rail query confirmed a monetary outcome; incident carries the reference.
    MonetaryReconciled { rail_reference: String },
}
```

### Health surface

Extend `ReceiptStoreHealthReport`
(`crates/kernel/chio-kernel/src/receipt_store.rs:100-117`) with two counts and fold
them into the `healthy` computation at `receipt_store.rs:614-631`:

```rust
#[serde(default)]
pub open_dispatch_intents: u64,
#[serde(default)]
pub dead_letter_dispatch_intents: u64,
```

```rust
let healthy = status.healthy
    && self.receipt_commit_actor.writer_counters().last_error.is_none()
    && dead_letter_dispatch_intents == 0;
```

This directly closes the "health lies" gap: an orphaned effect now flips the store to
unhealthy and appears in the CLI `trust receipt health` output
(`crates/products/chio-cli/src/cli/trust/receipt/health.rs:60-73`). Note that the
CLI opening its own store still cannot see a live kernel's in-memory writer counters;
persistent orphan and dead-letter rows are visible to any reader because they live in
the database, which is the point of making them durable. `open_existing` now also runs
the additive migration DDL when the on-disk schema predates the journal (see migration
notes below), so any connection built through `open` or `open_existing` has the table
by the time it returns; the counting queries still treat a missing
`chio_dispatch_intents` table as zero rows as a defensive fallback for a raw connection
that bypasses both open paths (for example a read-only health sampler). Live
writer-liveness polling is out of scope here and tracked separately in the wave-3
program.

The sanctioned remediation for a dead-letter incident is `chio receipt
resolve-dead-letter --request-id <id> [--tenant <tenant>] --note <note>`, backed by
`ReceiptStore::resolve_dead_letter_dispatch_intent`. It transitions the row to a
terminal `resolved` state that stops counting against `dead_letter_dispatch_intents`
(and therefore `healthy`) while appending the operator's note to the existing
resolution detail rather than overwriting it, so the row stays on disk as a complete,
auditable history. It refuses (fail-closed) when the request id does not name an
intent, or names one that is not currently `dead_letter` (still open, already
reconciled, or already resolved), so an operator cannot silently resolve the wrong
incident or resolve one twice. `chio receipt health`'s human output names this command
whenever `dead_letter_dispatch_intents` is nonzero.

### Config

Add to `KernelConfig`
(`crates/kernel/chio-kernel/src/kernel/kernel_struct.rs:10`):

```rust
/// Which call classes must write a durable dispatch intent before dispatch.
/// Default fails safe: cover every effecting class, exempt read-only.
pub dispatch_intent_journal: DispatchIntentJournalMode,
```

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchIntentJournalMode {
    /// No intent writes. Reintroduces the F04/F31/F70 window; operator opt-out only.
    Off,
    /// Write intents for SideEffecting and Monetary classes (default).
    SideEffecting,
    /// Write intents for every mediated call, including read-only.
    All,
}

impl Default for DispatchIntentJournalMode {
    fn default() -> Self {
        Self::SideEffecting
    }
}
```

Every `KernelConfig` construction site pins this field explicitly (Rust has no
struct-literal defaulting), so the file-config lowering layers are what let an
operator change it without a code change: the `receipts.dispatch_intent_journal`
key in a `chio.yaml`-configured deployment, and the `kernel.dispatch_intent_journal`
key in a policy-file-configured `chio-cli` deployment. Both lowerings default the
absent key to `Off`, not the enum's own compiled default, so upgrading a binary
never silently starts journaling for a deployment that has not opted in; a
present but unrecognized value rejects at config load time.

### Error taxonomy (typed, fail-closed)

`ReceiptStoreError` (`crates/kernel/chio-kernel/src/receipt_store.rs:151`) already
carries `Conflict`, `Pool`, `Sqlite`, and `Timeout`, which cover intent insert
collisions, saturation, disconnect, and commit failure. No new store variant is
required; reconciliation surfaces its own outcomes through
`DispatchIntentResolution` and the incident projection.

`KernelError` (`crates/kernel/chio-kernel/src/kernel/error.rs`) already has
`ReceiptPersistence(#[from] ReceiptStoreError)` at lines 156-157. Because a second
`#[from]` from the same source type is not allowed, add a distinct variant and map
into it explicitly at the intent-write site so a pre-effect deny is
distinguishable from a post-effect persistence failure:

```rust
#[error("dispatch intent persistence failed: {0}")]
DispatchIntentPersistence(String),
```

Fail-closed posture: an intent-write failure denies before any effect
(`build_receipt_persistence_failclosed_deny_response_with_metadata` shape). This is
strictly safer than today, where the equivalent failure surfaces only after the
effect has run.

### Crates, dirs, LOC, CI tier

- `crates/platform/chio-store-sqlite`: table DDL, `insert_dispatch_intent_tx`,
  `finalize_dispatch_intent_tx`, `reconcile_dispatch_intents`, per-op `Write`
  writer jobs. ~320 LOC + ~250 LOC tests.
- `crates/kernel/chio-kernel`: types (`DispatchIntentRecord`, `SideEffectClass`,
  `DispatchIntentKey`), trait methods, `record_dispatch_intent_if_side_effecting`,
  consume wiring in `record_chio_receipt`, health fields, config, boot hook. ~260
  LOC + ~200 LOC tests.
- No new crate. Unit and property tests run on the PR gate. Crash/kill-injection
  soak (SIGKILL between authorize/dispatch and receipt commit) runs nightly in the
  load-chaos program; the full power-loss simulation runs weekly. Honest PR-gate
  cost: intent unit and property tests add well under a minute; the nightly
  kill-injection soak is budgeted at roughly 15-20 minutes.

## Wire, schema, and receipt impact

- Signed receipt payloads are unchanged. No new receipt kind. The intent row is never
  signed and never entered into `chio_tool_receipts` or the Merkle tree, so
  checkpoint and inclusion-proof semantics (ADR-0008) are untouched.
- New non-audit SQLite table `chio_dispatch_intents` (schema above), created
  idempotently by the fresh-create path (`SqliteReceiptStore::open` /
  `open_with_pool_config`) via `CREATE TABLE IF NOT EXISTS`, and by
  `open_existing`'s additive migration when the on-disk schema revision
  predates the journal (the receipt-store schema revision is bumped 0 -> 1 for
  exactly this table); see migration notes below.
- `ReceiptStoreHealthReport` gains two `#[serde(default)]` count fields (additive,
  camelCase, backward compatible with existing JSON consumers).
- Any serialized intent record or reconciliation report uses RFC 8785 canonical JSON,
  consistent with `canonical_json_bytes` already used for `parameter_hash`.

## Migration and compatibility

- Backward compatible. The new table is additive, but not silently so for an
  older binary: the receipt-store schema revision is bumped 0 -> 1 for exactly
  this table, so an older binary's `FutureSchema` check refuses a database
  this journal has touched rather than silently serving without reconciling or
  surfacing rows it does not know about. Both `open` (fresh files, via the
  unconditional DDL) and `open_existing` (used by the CLI, `health.rs:43`, via
  the additive migration when the on-disk revision is older) create the table
  before returning. A raw connection that bypasses both open paths (a
  read-only sampler) must still treat a missing table as zero rows: a
  database that never journaled has no orphans, so this is an accurate
  report, not a fail-open of the invariant.
- No data migration: there are no historical intents. Existing receipts are
  unaffected.
- Staged rollout via `DispatchIntentJournalMode`. Ship defaulting to `Off` in the
  first release to de-risk latency, enable `SideEffecting` in the second once soak
  data is in hand, and make `SideEffecting` the compiled default in the third. The
  money path (F70) can be gated independently: enable intents for `Monetary` first,
  since that is the highest-consequence class.
- Operators enable the mode without a code change through the `dispatch_intent_journal`
  key: `receipts.dispatch_intent_journal` in a `chio.yaml`-configured deployment
  (`crates/platform/chio-config/src/schema.rs`), or `kernel.dispatch_intent_journal`
  in a policy-file-configured `chio-cli` deployment
  (`crates/platform/chio-control-plane/src/policy/types.rs`). Both accept `"off"`,
  `"side_effecting"`, or `"all"`; an absent key keeps `Off` regardless of the
  enum's own compiled default, and an unrecognized value rejects at config load
  time rather than silently falling back to a default.
- Health `healthy` tightening (dead-letter rows flip unhealthy) is behavior-visible
  to operators; document it in the release notes so a newly surfaced orphan is read
  as "recovery working", not "new fault".

## Test and verification plan

- Unit: intent insert collision on duplicate `request_id` fails closed; consume
  DELETE with mismatched `parameter_hash` aborts the batch and rolls back the receipt
  insert; read-only class writes no row.
- Property: for a random interleaving of appends and intents in one batch, after
  `commit_receipt_batch` every consumed intent is gone and every receipt is present,
  and no orphan is created for a committed receipt (the `receipt XOR open_intent`
  invariant).
- Loom: model the actor channel with concurrent `Intent` and `Append` (consume)
  commands plus a `Flush`, asserting no lost or double-consumed intent and correct
  `inflight` accounting, extending the existing writer-counter reasoning at
  `receipt_store.rs:168-199`.
- Crash/chaos (load-chaos program): SIGKILL the kernel at three injection points
  (after prepaid authorize at `async_evaluation_core.rs:469`, after tool dispatch at
  525-527, and mid-batch inside `append_receipt_batch`), restart, run
  `reconcile_dispatch_intents`, and assert every killed request resolves to either a
  durable receipt or a dead-letter incident, never silence. This is the specific test
  that proves the change: `intent_journal_crash_reconciles_every_effect`.
- Soak: sustained side-effecting load with periodic kills; assert
  `open_dispatch_intents` returns to zero after each reconciliation and TTFRH for
  read-only calls is unchanged within noise.
- Formal-methods tie-in: the `receipt XOR open_intent` invariant is stated as a state
  predicate for the receipt-durability model in the formal-methods plan; the loom and
  property tests are its executable witnesses.

## Acceptance criteria

- Killing the kernel at any of the three injection points above and restarting yields,
  for every in-flight side-effecting/monetary request, exactly one of: a durable
  receipt, or a dead-letter incident with a recorded `request_id`. Never neither.
- After reconciliation of a clean run, `open_dispatch_intents == 0` and
  `dead_letter_dispatch_intents == 0`, and `receipt_store_health().healthy == true`.
- A monetary orphan produces an incident that names the `rail` and, when available,
  the `rail_authorization_id`, so an operator can reconcile against the rail without
  guessing the reference.
- Read-only calls write no intent row and show no measurable TTFRH regression.
- An intent-write failure denies before dispatch (no effect, no rail call), surfaced
  as `KernelError::DispatchIntentPersistence`.

## Risks and alternatives

- Added latency on effecting paths. Each side-effecting or monetary call pays one
  extra durable round-trip before dispatch. It group-commits with other intents
  (same 64/500us batching) and is dwarfed by the external tool or rail call that
  follows, so relative overhead is small; read-only calls pay nothing. Mitigation:
  the class gate and `DispatchIntentJournalMode` bound the cost precisely, and the
  soak measures it before `SideEffecting` becomes default.
- Write amplification: two extra statements per effecting call (one insert
  pre-dispatch, one delete at consume). Both are keyed on `request_id` and ride
  existing transactions; measured impact is expected to be minor and is a soak gate.
- Reconciler correctness: a wrong `SafeToReplay` decision could re-run a side effect.
  Mitigation: the default is `DeadLetter`; `SafeToReplay` requires the reconciler to
  prove idempotence, and monetary calls never replay blindly (rail query only).
- Alternative considered and rejected: a per-kernel append-only WAL file separate
  from SQLite. Rejected because ADR-0013 already commits to a WAL-fsync-before-allow
  model inside the store, and a second write-ahead surface would duplicate durability
  machinery, complicate recovery ordering, and not give the same-transaction consume
  guarantee that a shared SQLite transaction gives for free.
- Alternative considered and rejected: making the intent a real signed receipt kind.
  Rejected because it would inflate the Merkle-committed log with speculative,
  frequently-consumed rows and disturb ADR-0008's count-based checkpoint sizing; the
  intent is operational state, not attestation.
- Alternative considered and rejected: blind replay of orphaned intents on boot.
  Rejected because side effects are not generally idempotent; replay could double a
  payment. Dead-letter-by-default is the fail-closed choice.

## Rollout and sequencing

1. RFC-0006 lands first: it bounds the receipt-store append cost and fixes
   single-writer discipline for the store this journal rides on (RFC-0006 sequences
   itself ahead of this RFC for exactly that reason). Boot reconciliation and the
   dead-letter incident record are self-contained in this RFC; alert routing for a
   nonzero `dead_letter_dispatch_intents` count rides the RFC-0009 observability and
   alerting wiring.
2. This RFC (RFC-0003) lands next: schema, per-op dispatch-intent writer jobs, same-transaction
   consume, kernel wiring, health fields, config defaulting to `Off`, and the
   operator-facing `dispatch_intent_journal` config key (`receipts.dispatch_intent_journal`
   in `chio.yaml`, `kernel.dispatch_intent_journal` in a `chio-cli` policy file) so a
   file-configured deployment can flip the mode without a code change.
3. Enable `Monetary` then `SideEffecting` via config after nightly kill-injection soak
   is green; promote `SideEffecting` to compiled default.
4. RFC-0013 extends the money path: it upgrades `rail_authorization_id` handling into
   a full payment journal and adds the `PaymentAdapter` capture/release idempotency
   contract keyed on `(authorization_id, request_id)`, enabling safe rail-side replay
   during reconciliation. RFC-0003's `rail` / `rail_authorization_id` columns and the
   `MonetaryReconciled` resolution are the durable substrate it builds on.
