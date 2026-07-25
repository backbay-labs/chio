# WS1 First Light Phase 1 Implementation Plan

> **For agentic workers:** Execute this plan task by task. Keep each red/green
> cycle focused, and do not begin Phase 2 work from this document.

**Goal:** Land two independent fail-closed corrections: F72 denies an
uncomparable spend cap, and the F68 foundation routes every settlement-observer
status instead of discarding it.

**Scope:** Phase 1 does not add the `economy` config block, control-plane
installers, a production settlement driver, a payment rail, a price-oracle
installer, or a credit driver. Those components land together only after their
normative contracts exist. Phase 2 is hard-gated on RFC-0003. Phase 3 installs
the real economy components and the F69 production driver through the paired
observer runtime established here.

**Architecture:** `BudgetTree::evaluate` returns a typed
`CurrencyMismatch` denial whenever a node has a spend cap but the draft has no
currency or a different currency. The kernel replaces the discarded
`SettlementObserverStatus` with a router. The router treats registered
observer outcomes as follows:

- `Accepted`, pre-hook `Skipped`, and `NotRegistered` do not create unresolved
  work when their required cleanup succeeds; an accepted/skipped cleanup-store
  failure is unresolved and counted. A hook-returned `Skipped` is an invalid
  outcome for a positive economic observation and dead-letters fail closed.
- `Retryable` and transient hook failures atomically advance a durable retry
  row under the existing `chio_settle::RetryPolicy`.
- `Permanent` and permanent hook failures atomically create a dead letter.
- Before any registered observer runs, the receipt-writer transaction seeds a
  due `pending_observation` attempt-zero row. Inline routing and the recovery
  worker use the same leased compare-and-swap contract, so a process crash does
  not create an unobservable gap between receipt commit and routing.
- Every retryable, permanent, or hook-failed status emits a warning and
  increments `chio_settlement_unresolved_total`, whether persistence succeeds
  or fails. Persistence failure is included as bounded structured warning
  context; it never changes signed receipt bytes or rolls back an already
  committed tool call.

The SQLite implementation performs read, classify, retry upsert, and
dead-letter transition in one `TransactionBehavior::Immediate` transaction.
This deliberately tightens RFC-0013's illustrative read-then-upsert sequence,
which is not safe under concurrent observations.

## Non-Negotiable Invariants

- Keep the receipt-store write lock boundary unchanged, but extend its existing
  transaction to seed attempt zero before commit. Settlement observation and
  routing run only after the receipt and pending work are durable and the lock
  is released.
- A routing failure is fail-loud but cannot mutate or invalidate the signed
  receipt. Later settlement state is a separate artifact.
- Preserve retry timing in milliseconds. Store `next_visible_at_ms` and compute
  it with `Duration::as_millis()` plus checked conversion. Never
  use `Duration::as_secs()` for the default 250 ms and 500 ms backoffs.
- A receipt has at most one active retry row and at most one dead-letter row.
  The retry-to-dead-letter transition is atomic.
- Dead-letter insertion is idempotent only for byte-identical records. A
  different record for the same receipt is a conflict, warning, and unresolved
  metric increment.
- Do not expose `Keypair`, add a signing-key accessor, or add a public
  receipt-persistence method for tests. Kernel routing tests belong in the
  crate's existing internal test module and use its support builders.
- Do not add no-op `configure_*` functions. A future installer must validate
  and install a real component in the same change.
- `chio-settle` owns the retry-store contract because both the kernel producer
  and the Phase 3 settlement runtime consume it. The runtime must drain due
  `settle_attempts`; a receipt or obligation scan is not a substitute for the
  persisted retry deadline and dead-letter state.
- Phase 1 closes F68's silent-drop defect and F72. It does not implement the
  F69 production driver or close the production money loop; those claims require
  Phase 3 integration and Phase 4 end-to-end proof.
- No `.unwrap()` or `.expect()` in non-test code. No em dashes in code,
  comments, or documentation.

## Task 1: Deny Uncomparable Spend Caps (F72)

**Files:**

- Modify `crates/economy/chio-metering/src/budget_hierarchy.rs`

### 1.1 Write the failing tests

Add focused tests beside the existing `BudgetTree` tests:

- A node capped in USD and a USD draft within the cap remains allowed.
- A node capped in USD and an EUR draft returns
  `BudgetDecision::Deny { reason: BudgetDenyReason::CurrencyMismatch { ... }
  }`.
- A node with a spend cap and a draft without currency returns the same typed
  denial.
- A USD-capped node with a USD draft and a nonzero EUR current-spend snapshot
  denies instead of adding EUR units to USD units.
- A nonzero current-spend snapshot without currency denies; a zero snapshot
  with no currency remains valid and adopts the matched draft currency.
- A node without a spend cap is unaffected by an absent draft currency.
- In a multi-node path, any capped node with an uncomparable currency denies;
  another matching node must not hide it.

Run one filter per command:

```bash
cargo test -p chio-metering budget_tree_allows_matching_currency
cargo test -p chio-metering budget_tree_denies_mismatched_currency
cargo test -p chio-metering budget_tree_denies_missing_currency
```

Confirm the new denial tests fail before changing evaluation.

### 1.2 Add the denial and replace the skip

Add this semantic variant to `BudgetDenyReason` using the crate's actual node
and currency types:

```rust
CurrencyMismatch {
    node: BudgetNodeId,
    node_currency: Option<String>,
    current_currency: Option<String>,
    draft_currency: Option<String>,
},
ArithmeticOverflow {
    node: BudgetNodeId,
    dimension: String,
},
```

At the spend-cap branch in `BudgetTree::evaluate`:

1. If no spend cap exists, continue evaluating the remaining constraints.
2. If a spend cap exists, require the node and draft currencies to be present
   and equal. If current spend is nonzero, its currency must also be present and
   equal. A zero current-spend value may have no currency; a present current
   currency must still match.
3. When these conditions fail, record `CurrencyMismatch` as the current node's
   offender and continue to the next ancestor. This preserves the evaluator's
   existing closest-to-root offender rule while preventing other dimensions on
   the same node from hiding the currency defect.
4. Only add and compare minor units after all applicable currencies match. Use
   checked addition for spend units and deny on arithmetic overflow; do not let
   `AggregateSpend::saturating_add` turn an overflow into an allowed amount when
   the configured cap is `u64::MAX`.

Do not perform conversion in `BudgetTree`. Cross-currency conversion belongs at
the already defined price-oracle boundary, before budget evaluation.

### 1.3 Verify Task 1

```bash
cargo test -p chio-metering budget_tree_
cargo clippy -p chio-metering -- -D warnings
```

Acceptance:

- No capped node can be skipped because its amount is uncomparable.
- Matching-currency behavior is unchanged.
- The denial carries enough context for an operator to identify both
  currencies and the denying node.

## Task 2: Define the Routing Contract

**Files:**

- Add `crates/economy/chio-settle/src/outcome_store.rs`
- Modify `crates/economy/chio-settle/src/lib.rs`
- Modify `crates/economy/chio-settle/src/hook.rs`
- Add `crates/kernel/chio-kernel/src/settlement_routing.rs`
- Modify `crates/kernel/chio-kernel/src/lib.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/settlement_observer.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/kernel_struct.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/construction.rs`
- Modify `crates/kernel/chio-kernel/src/receipt_store.rs`

### 2.1 Preserve hook failure class

`SettlementObserverStatus::HookFailed` currently retains only a string, and
observation construction collapses integrity failures into `Skipped`. Replace
both with typed, bounded classification so the router never retries a known
permanent failure or silently skips an invalid money receipt:

```rust
pub enum SettlementFailureClass {
    Retryable,
    Permanent,
}

pub enum SettlementFailureCode {
    InvalidReceiptSignature,
    InvalidActionHash,
    UntrustedReceiptSigner,
    MalformedFinancialMetadata,
    InvalidObservation,
    Rpc,
    InvalidInput,
    InvalidDispatch,
    InvalidBinding,
    Unsupported,
    Serialization,
    Signature,
    Verification,
    Backend,
}

pub struct SettlementFailureReason {
    code: SettlementFailureCode,
    detail_sha256: [u8; 32],
}

HookFailed {
    class: SettlementFailureClass,
    reason: SettlementFailureReason,
}
```

Observation construction returns a typed result: only a denied call, a receipt
with no authorized economic intent, or an allowed zero-charge receipt may return
the closed `SettlementSkipReason` enum. Invalid receipt signature, invalid action
hash, an untrusted kernel key, or malformed positive financial metadata returns
a permanent `SettlementFailureReason`. Preserve the original detail only long
enough to compute its digest and pass it through the repository redaction
boundary for bounded logs; never persist or label the raw string.

These changes define the pre-release observer-status v1 wire shape. Keep
`SETTLEMENT_OBSERVER_STATUS_SCHEMA` at `chio.settle.observer-status.v1`; no
released compatibility contract requires a speculative v2 tag.

Map `SettlementHookError::InvalidObservation` and
`SettlementHookError::Permanent` to `Permanent`, and
`SettlementHookError::Transient` to `Retryable`. For
`SettlementHookError::Pipeline`, inspect the typed `SettlementError`: only
`Rpc` is presumptively retryable; `InvalidInput`, `InvalidDispatch`,
`InvalidBinding`, `Unsupported`, `Serialization`, `Signature`, and
`Verification` are deterministic and permanent. Add unit tests for every error
variant. Do not infer failure class from display text.

### 2.2 Define the leased atomic store contract

`chio-settle` owns the persistence interface; `chio-store-sqlite` implements
it, and `chio-kernel` depends on it without reversing the existing dependency
direction. Do not put the trait in `chio-kernel`: the Phase 3 runtime belongs in
`chio-settle`, so that placement would force a dependency cycle.

Define a kernel-independent routing input beside the trait:

```rust
pub enum SettlementRoutingInput {
    Accepted,
    Skipped { reason: SettlementSkipReason },
    Retryable { reason: SettlementFailureReason },
    Permanent { reason: SettlementFailureReason },
}

pub struct SettlementAttemptClaim {
    pub receipt_id: String,
    pub finalized_at: u64,
    pub attempts: u32,
    pub row_version: u64,
    pub lease_owner: String,
    pub lease_token: String,
    pub lease_until_ms: u64,
}
```

Keep the interface backend-neutral and object-safe. It exposes guarded claim
operations and one atomic transition for a claimed normalized outcome, not
public `load` plus `upsert` methods:

```rust
pub trait SettlementOutcomeStore: Send + Sync {
    fn settlement_store_binding(&self) -> SettlementStoreBinding;

    /// Claim one due row by receipt id for the inline observer. Returns None if
    /// another live lease owns it.
    fn claim_receipt(
        &self,
        receipt_id: &str,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError>;

    /// Claim a bounded due batch for restart recovery using the same CAS rules.
    fn claim_due(
        &self,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<SettlementAttemptClaim>, SettlementRouteError>;

    fn record_claimed_outcome(
        &self,
        claim: &SettlementAttemptClaim,
        outcome: &SettlementRoutingInput,
        policy: RetryPolicy,
        observed_at_ms: u64,
    ) -> Result<SettlementRoute, SettlementRouteError>;
}
```

The kernel-owned `ReceiptStore` trait separately gains
`append_chio_receipt_with_pending_observation(receipt, pending)` and an
explicit `AtomicReceiptProjection` capability reported at construction. Its
default implementation returns `Unsupported`; it must never append only the
receipt. Installing a paired observer runtime requires that capability up front.
`SqliteReceiptStore` implements the method by inserting the receipt and
attempt-zero row through its single writer and one transaction. This keeps the
outcome-store trait independent of a SQLite transaction type while making the
atomic boundary enforceable for every backend.

Both store traits also expose a fixed-size `SettlementStoreBinding` generated
once by the durable writer. The receipt-store view returns the binding only when
it can seed the atomic projection, and every outcome-store view returns the
binding of the writer it uses. Installation requires exact equality. A
standalone outcome store receives a distinct binding and cannot satisfy the
paired installer; `open_alongside` copies the receipt writer's binding. The
binding contains no database path or credential material.

Use bounded result variants:

```rust
pub enum SettlementRoute {
    NoAction,
    RetryScheduled {
        attempt: u32,
        next_visible_at_ms: u64,
    },
    DeadLettered {
        attempts: u32,
    },
}
```

Define the error surface in the same settle-owned module:

```rust
pub enum SettlementRouteError {
    Backend { detail: String },
    Conflict { detail: String },
    InvalidRecord { detail: String },
}

pub enum SettlementRouteErrorClass {
    Backend,
    Conflict,
    InvalidRecord,
}
```

`SettlementRouteError::class()` returns the bounded enum. Runtime warnings log
only that class, never the unbounded `detail`; the detail remains available to
the direct caller and must pass the repository's log-redaction boundary before
any operator presentation. Persist only the closed reason code and fixed-size
detail digest. `DeadLetterRecord` changes its free-form reason/pipeline-error
fields to the same bounded representation.

The interface contract requires:

- A newly inserted receipt seeds exactly one `pending_observation` row with
  attempt zero, version zero, no lease, and an immediately due visibility time
  in the same writer transaction. A byte-identical duplicate receipt append is a
  no-op and never recreates work that an accepted or skipped transition already
  removed. The paired append path does not retrofit receipts written before the
  observer runtime was installed. Any sidecar conflict while inserting a new
  receipt aborts the entire transaction.
- `claim_receipt` and `claim_due` update only an unleased or expired due row,
  increment its version with checked arithmetic, and attach a fresh unpredictable
  lease token and bounded lease deadline. The returned claim also carries the
  persisted finalization time, attempt count, and lease owner. A worker runs the
  hook only after this claim transaction commits.
- `record_claimed_outcome` requires the exact receipt id, finalization time,
  attempt count, row version, lease owner, lease token, lease deadline, and an
  unexpired lease. Its delete, retry update, or retry-to-dead-letter transition
  uses a `WHERE` clause over all persisted claim fields. Zero affected rows is
  `Conflict`; a stale worker can never commit over a newer lease.
- `Skipped` and `Accepted` return `NoAction` and remove the claimed row if
  the caller holds its lease, but never silently remove a dead letter.
  `NotRegistered` never receives attempt-zero work and never reaches the store.
- `Retryable` calls `classify_attempt` with the persisted attempt
  count and atomically upserts the returned next attempt.
- `Permanent` dead-letters immediately.
- `next_visible_at_ms` is `observed_at_ms + backoff_ms` using checked
  arithmetic; overflow is `InvalidRecord`.
- Exhaustion inserts the dead letter and deletes the attempt row in the same
  transaction.
- An existing dead letter is terminal for every later input until an operator
  explicitly clears it. A retryable input cannot recreate an attempt row;
  accepted or skipped input cannot clear it; a byte-identical terminal input is
  idempotent; a different terminal record is a conflict. Exact terminal replay
  is the only path that may inspect terminal state without a live attempt row: it
  reconstructs the canonical record from the persisted claim values and
  supplied typed outcome, compares bytes, and performs no mutation.
- A backend error or process crash before claim leaves attempt zero due. A crash
  after claim, including after the hook returns but before the outcome CAS,
  leaves the row recoverable when the lease expires. Startup and the periodic
  worker drain due rows; neither scans receipts as a substitute.

In the kernel router, map `SettlementObserverStatus` to the settle-owned input:
`Observed::Accepted`/`Retryable`/`Permanent` map directly; a hook-returned
`Observed::Skipped` is a contract violation mapped to permanent
`InvalidObservation`; pre-hook `Skipped` maps directly; `HookFailed` maps by its
typed failure class; `NotRegistered` returns before mapping. Never parse display
strings to make this decision.

Replace the independent observer field and setter with one optional internal
`SettlementObserverRuntime` holding the hook, `Arc<dyn
SettlementOutcomeStore>`, and `RetryPolicy`. Its public installer requires all
three arguments in one call, so a registered observer cannot exist without
durable routing, validates the retry policy, and requires matching receipt and
outcome store bindings. The no-observer default remains `None`. Keep the observer
accessor limited to its public hook handle; do not expose keys or persistence
  internals. In Phase 3, the production assembler must use this paired installer,
  and startup validation must reject any `driver = ops` configuration that cannot
  construct the hook and store together. The settle-owned contract above is also
  the Phase 3 retry-worker contract; do not add a second queue API or move the
  contract into the kernel.

Add `RetryPolicy::validate()` and call it in the public installer and store
entrypoint. `max_retries = 0` remains a valid no-retry policy, but values above
32 reject; `initial_backoff_ms` and `backoff_cap_ms` must be nonzero,
`initial_backoff_ms <= backoff_cap_ms <= 86_400_000`, and
`backoff_multiplier` must be in `1..=16`. Invalid policy is a startup/config
error, not a zero-delay loop. Visibility-deadline addition is checked; overflow
returns `InvalidRecord` instead of saturating.

Claim inputs are bounded at the store boundary before a transaction starts:
worker ids are nonempty and at most 128 bytes, lease duration is in
`1..=86_400_000` milliseconds, and due-batch limits are in `1..=1024`. The
runtime supplies the clock values at this trusted boundary. Invalid bounds or
overflow return `InvalidRecord` without changing durable state.

Correct the current comments in `chio-settle/src/hook.rs` and
`kernel/construction.rs`: a hook returns an outcome, while retry/dead-letter
routing is durable only when invoked through the paired kernel observer runtime.
Neither comment may imply that a standalone hook call is automatically routed.

### 2.3 Unit-test the contract without a public test seam

Add pure tests for the settle-owned routing types, then a small in-memory fake
store inside `settlement_routing.rs` tests. Test status normalization and
failure classification directly. Integration tests that need
`record_chio_receipt` land under `kernel/tests` in Task 4, where private methods
are already accessible.

Run:

```bash
cargo test -p chio-settle
cargo test -p chio-kernel settlement_routing
cargo test -p chio-kernel settlement_observer
```

## Task 3: Implement the Atomic SQLite Ledger

**Files:**

- Add `crates/platform/chio-store-sqlite/src/settle_attempts.rs`
- Modify `crates/platform/chio-store-sqlite/src/dead_letters.rs`
- Modify `crates/platform/chio-store-sqlite/src/receipt_store.rs`
- Modify `crates/platform/chio-store-sqlite/src/receipt_store/bootstrap/open.rs`
- Modify `crates/platform/chio-store-sqlite/src/receipt_store/support/store_impl.rs`
- Modify `crates/platform/chio-store-sqlite/src/lib.rs`

### 3.1 Add the migration

Create `settle_attempts` with explicit millisecond columns:

```sql
CREATE TABLE IF NOT EXISTS settle_attempts (
    receipt_id           TEXT PRIMARY KEY,
    finalized_at         INTEGER NOT NULL,
    work_kind            TEXT NOT NULL CHECK (
                            work_kind IN ('pending_observation', 'retry_scheduled')
                         ),
    attempts             INTEGER NOT NULL,
    next_visible_at_ms   INTEGER NOT NULL,
    row_version          INTEGER NOT NULL,
    lease_owner          TEXT,
    lease_token          TEXT,
    lease_until_ms       INTEGER,
    reason_code          TEXT,
    reason_detail_sha256 BLOB CHECK (
                            reason_detail_sha256 IS NULL OR
                            length(reason_detail_sha256) = 32
                         ),
    CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_until_ms IS NULL) OR
           (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until_ms IS NOT NULL)),
    CHECK ((reason_code IS NULL AND reason_detail_sha256 IS NULL) OR
           (reason_code IS NOT NULL AND reason_detail_sha256 IS NOT NULL)),
    updated_at_ms        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_settle_attempts_visible
    ON settle_attempts(next_visible_at_ms, lease_until_ms, receipt_id);
```

An attempt-zero row has `work_kind = 'pending_observation'`, `attempts = 0`,
`row_version = 0`, and NULL lease and reason fields. A retry row has
`work_kind = 'retry_scheduled'` and a bounded reason pair. Checked conversions
reject negative or out-of-range persisted integers.

Keep the `settle_dead_letters` primary key, but define one bounded v1
dead-letter body that stores only `reason_code` and the 32-byte detail digest.
New writes accept only that exact v1 shape and use RFC 8785 canonical JSON.
Unknown or obsolete bodies fail closed. Add database guards
preventing an attempt insert while the same receipt is dead-lettered and
preventing an independent dead-letter insert while an attempt exists. The atomic
transition deletes the attempt before inserting the terminal row inside one
transaction. Run both additive migrations from the same store constructor.
Advertise `SettlementObservationV1` only when the live `sqlite_master` manifest
matches the reference tables, indexes, and every trigger on both settlement
tables. Missing, rewritten, or extra triggers disable the capability. After a
new attempt-zero insert, read back and compare the complete projected row before
committing the receipt transaction.

### 3.2 Implement `SettlementOutcomeStore`

When opened alongside `SqliteReceiptStore`, execute the write through its
existing `WriterHandle`, as `SqliteIouEnvelopeStore` does; do not bypass the
single-writer discipline with a direct pool write. Use
`rusqlite::TransactionBehavior::Immediate` inside that writer operation. The
standalone constructor may transact directly on its owned connection, but is
test/tooling-only and cannot satisfy the paired runtime's atomic receipt
projection capability. Within one transaction:

1. Validate the retry policy, worker/lease/batch bounds, and checked integer
   conversions before mutation.
2. For claims, select a due row and update `row_version`, lease fields, and
   `updated_at_ms` using one guarded statement; return only the newly committed
   claim values.
3. For claimed completion, read terminal state first only to support an exact
   idempotent terminal replay after the attempt row was removed. Reconstruct the
   expected canonical bytes from the claim and outcome; exact equality returns the
   existing terminal result without mutation, and every other case is
   `Conflict`.
4. When no terminal row exists, verify the complete claim and its unexpired
   lease against the current attempt row before reading or mutating work state.
5. Classify the normalized outcome using `chio_settle::classify_attempt` and the
   attempt count carried by the verified claim.
6. For retry, increment the attempt count, set
   `work_kind = 'retry_scheduled'`, clear the lease, and write the millisecond
   visibility deadline.
7. For dead letter, compute attempts as `persisted_attempt.checked_add(1)`;
   direct permanent failure records 1, and a permanent or exhausted result after
   persisted attempt `n` records `n + 1`. Overflow is `InvalidRecord`. Delete the
   retry row, then insert or verify the canonical row before commit.
8. For accepted or skipped status, delete only the claimed row when no terminal
   row exists.
9. Commit and return the bounded `SettlementRoute`.

All integer conversions must be checked. Conversion and serialization errors
return `InvalidRecord`, a conflicting dead letter returns `Conflict`, and pool
or SQLite failures return `Backend`. Every error leaves the transaction
uncommitted.

Do not implement this as `get_attempt` followed by `upsert_attempt`; that split
reintroduces lost updates and duplicate terminal transitions.

### 3.3 Test persistence and concurrency

Add tests using the existing `chio_test_support::prelude::*` conventions:

- Migration is idempotent.
- Attempt-zero seeding is atomic with a new receipt append; byte-identical receipt
  replay never resurrects completed work, and a forced failure leaves neither
  receipt nor attempt row.
- An obsolete unbounded v1 body and unknown schema tags fail closed.
- Claiming writes a unique token and increments the version; a concurrent or
  stale claim cannot commit an outcome.
- Crashes before the hook, after the hook but before outcome CAS, and after a
  successful CAS leave respectively one recoverable row, one lease-recoverable
  row, and exactly one terminal transition.
- First retry stores attempt 1 at `observed_at_ms + 250`.
- Second retry stores attempt 2 at `observed_at_ms + 500`.
- Permanent outcome creates one dead letter and no retry row.
- Invalid retry-policy fields reject before any row changes; reason codes round
  trip and every persisted detail digest is exactly 32 bytes with no raw error
  text.
- Retry exhaustion atomically replaces the attempt row with one dead letter.
- Accepted and skipped outcomes clear an attempt but not a dead letter.
- Repeating an identical dead letter is idempotent.
- A different dead letter for the same receipt is a conflict.
- A retryable, accepted, or skipped status after dead-lettering cannot resurrect
  or clear terminal state; only the explicit operator clear API can do so.
- Concurrent transitions for one receipt, tested with a file-backed temporary
  database rather than isolated `:memory:` connections, produce no lost row
  and at most one dead letter.
- A forced transaction failure leaves the prior state intact.

Run:

```bash
cargo test -p chio-store-sqlite settle_attempt
cargo test -p chio-store-sqlite dead_letter
cargo clippy -p chio-store-sqlite -- -D warnings
```

## Task 4: Route the Observer Status and Export the Metric

**Files:**

- Modify `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs`
- Modify `crates/kernel/chio-kernel/src/observability/metrics.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/tests.rs`
- Add `crates/kernel/chio-kernel/src/kernel/tests/settlement_routing.rs`
- Modify `crates/observability/chio-metrics-spec/src/lib.rs`
- Modify `crates/observability/chio-metrics-spec/src/runtime.rs`
- Modify `crates/observability/chio-metrics-spec/metrics.snapshot`

### 4.1 Register one real metric family

Add `CHIO_SETTLEMENT_UNRESOLVED_TOTAL` as an unlabeled counter in the metrics
registry and runtime families. Preregister and render the same family through
the kernel metrics endpoint. Use the shared runtime counter directly; do not
create a second shadow `AtomicU64` with a different value.

Regenerate or update `metrics.snapshot` through the crate's established
snapshot workflow and run:

```bash
cargo test -p chio-metrics-spec golden_snapshot_matches_registry
```

### 4.2 Replace the discard

In `record_chio_receipt`, use the receipt store's existing `WriterHandle` to
append the receipt and seed its `pending_observation` row in one
`TransactionBehavior::Immediate` transaction whenever the paired observer
runtime is installed. Any seed failure aborts the append; a backend that cannot
share this writer is rejected when the runtime is installed. After commit and
after releasing the receipt-store lock, claim by receipt id and route the
returned status:

```rust
let claim = match self.claim_settlement_observation(receipt) {
    Ok(Some(claim)) => claim,
    Ok(None) => return Ok(()), // another live claimant owns the durable row
    Err(error) => {
        self.record_unresolved_claim_failure(receipt, &error);
        return Ok(());
    }
};
let status = self.run_settlement_observer(receipt);
self.route_claimed_settlement_status(receipt, &claim, &status);
Ok(())
```

A post-commit claim failure is warning-visible and counted once while the
durable row remains due or leased for recovery. It cannot roll back the already
completed tool result. Only a pre-commit attempt-zero seed failure aborts receipt
persistence.

The routing method has these observable rules:

- `NotRegistered` returns without warning or metric.
- Registered accepted or skipped outcomes call the paired installed store so
  stale retry state can be cleared. The installer makes a registered observer
  without that store unrepresentable. A cleanup-store error is itself unresolved:
  warn with its bounded class and increment the unresolved counter once, because
  stale retry work may otherwise survive.
- Retryable, permanent, and failed-hook statuses require durable routing. Warn
  with `receipt_id`, a bounded outcome class, and a bounded persistence result,
  then increment `chio_settlement_unresolved_total` exactly once. This applies
  to successful retry scheduling and dead-lettering as well as store-error
  cases, because the underlying settlement did not succeed.
- A successful retry schedule or dead-letter transition is durable. A store
  error changes only the warning's bounded persistence result; it must not cause
  a second metric increment for the same routing invocation.
- Never include auth, raw receipt metadata, or unbounded backend error content
  in metric labels. The counter is unlabeled; structured detail belongs in the
  bounded warning. The production router increments the shared runtime metric
  through a private `SettlementRoutingMetrics` sink; internal tests inject a fake
  sink to prove exact call counts without adding a public test API or a shadow
  production counter.

### 4.3 Add internal kernel tests

Register `kernel/tests/settlement_routing.rs` from the existing test module.
Use current support builders and private method access. Do not add a public key
or persistence accessor. Cover:

- No observer preserves current behavior and produces no routing call.
- A registered observer receives no hook call unless receipt and attempt zero
  committed together; a seed failure leaves neither row.
- Installation rejects a missing or mismatched settlement writer binding even
  when both store handles otherwise report supported capabilities.
- A crash immediately after commit, after claim, and after hook return is
  recovered through the same leased claim path without losing the receipt.
- Accepted and pre-hook skipped statuses clear stale attempts; hook-returned
  skipped is permanent invalid observation.
- Accepted/skipped cleanup-store errors are warning-visible, counted once, and
  leave the stale row intact.
- Retryable, permanent, and hook-failed statuses reach the store.
- Invalid signature, action hash, signer trust, or positive financial metadata
  becomes typed `Permanent`; only deny, non-economic, and zero-charge receipts
  become `Skipped`.
- Internal fake-sink tests assert exactly one metric call for each retry schedule,
  dead letter, unresolved cleanup, and store error and zero for clean
  accepted/skipped/not-registered routes. The metrics-endpoint integration test
  only proves that the shared production family is registered and increases;
  process-global deltas are not used to claim exactly-once behavior.
- Receipt append succeeds even when routing fails.
- The receipt is already queryable when the fake store is invoked.
- Concurrent calls do not hold the receipt-store write lock across routing.
- A stale lease token or row version cannot delete, retry, or dead-letter work
  owned by a newer claimant.

Retain the existing black-box byte identity test:

```bash
cargo test -p chio-kernel settlement_routing
cargo test -p chio-kernel --test settlement_observer_byte_identity
cargo test -p chio-kernel metrics_endpoint
cargo clippy -p chio-kernel -- -D warnings
```

Acceptance:

- There is no `_settlement_status` discard.
- Any unresolved registered-observer status is both loud and counted.
- The router cannot change canonical receipt bytes or the dispatch result.
- Tests use no new public test-only API.

## Task 5: Phase Gate and Claim Audit

### 5.1 Focused regression gate

```bash
cargo test -p chio-metering budget_tree_
cargo test -p chio-settle outcome_store
cargo test -p chio-store-sqlite settle_attempt
cargo test -p chio-store-sqlite dead_letter
cargo test -p chio-kernel settlement_routing
cargo test -p chio-kernel --test settlement_observer_byte_identity
cargo test -p chio-metrics-spec golden_snapshot_matches_registry
```

### 5.2 Workspace gate

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
git diff --check
```

If the workspace has an environmental failure, capture the exact command and
failure, reproduce it on the same `origin/main`, and report the comparison. Do
not relabel a new failure as pre-existing without that proof.

### 5.3 Documentation and claim checks

```bash
rg -n "let _settlement_status|Duration::as_secs\(\)|signing_keypair|record_chio_receipt_for_test" \
  docs/superpowers/plans/2026-07-10-ws1-first-light-phase1.md
rg -n "configure_\\*|configure_settlement|configure_payment_rail|configure_price_oracle" \
  docs/superpowers/plans/2026-07-10-ws1-first-light-phase1.md
rg -n $'\u2014' \
  crates/economy/chio-metering \
  crates/kernel/chio-kernel \
  crates/platform/chio-store-sqlite \
  crates/observability/chio-metrics-spec
```

Expected:

- The first search finds only explicit prohibitions and the search command,
  never an implementation instruction.
- The second search finds only the no-op-installer prohibition and the search
  command, never a Phase 1 task.
- The em-dash search returns no matches in changed content.

## Phase 1 Exit Criteria

- F72 denies every uncomparable capped amount and preserves matching-currency
  behavior.
- The settlement status is no longer discarded.
- Retry and dead-letter persistence uses one atomic transaction and preserves
  sub-second backoff.
- Every registered-observer receipt commits with attempt-zero work; lease/CAS
  recovery closes the crash window before inline routing.
- Every unresolved outcome is warning-visible and increments the shared metric
  family once, including durable retry or dead-letter transitions and failed
  persistence.
- Receipt bytes and the post-dispatch success path remain unchanged.
- No config or installer that installs nothing has been introduced.
- Focused and workspace gates are green, or any baseline environmental failure
  is demonstrated against the same `origin/main`.
- The PR description says Phase 1 closes F68's silent status drop and F72. It
  does not claim a production economy loop or the F69 production settlement
  driver.
