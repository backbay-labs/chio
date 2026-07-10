# RFC-0013: Money-path durability: payment journal, hold sweeper, settlement routing, fail-closed caps

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0006 (monetary budget semantics), ADR-0015 (predeclared escrow circuit breakers)
- Depends on: RFC-0003 (durable dispatch-intent journal)
- Closes findings: F70, F71, F68, F69, F72, F73, F74 (see ./README.md and the wave-3 readiness review)

## Summary

The economy subsystem moves external funds before it writes any durable, attested
record of the movement, leaks budget capacity on every crash, and drops the
settlement outcome on the floor at its only production call site. This RFC makes the
money path crash-safe and fail-closed. It adds a durable `payment_journal` co-located
with the budget holds (written before `adapter.authorize`, advanced around
capture/release, closed after the receipt persists, reconciled on boot via an
idempotent adapter query); a boot-plus-periodic sweeper for orphaned budget holds; a
routing consumer that feeds the discarded settlement-observer outcome into the
existing `classify_attempt` retry envelope and `SqliteDeadLetterStore`; the intended
production `SettlementHook` driver seam; a fail-closed `Deny(CurrencyMismatch)` in
`BudgetTree` instead of a silent skip; a durable SQLite EIP-3009 nonce store; and a
durability caveat plus snapshot seam for the process-local `BudgetEnforcer`. It is the
money-path specialization of RFC-0003: RFC-0003 owns the generic
`receipt XOR open_intent` guarantee and delegates monetary orphans to the reconciler
specified here.

## Motivation

Read against the Ubicloud "PostgreSQL and the OOM Killer" lens: when a component dies
mid-operation, internal accounting must be trustworthy or loudly broken, the blast
radius must be knowable, and recovery must be durable. On the money path today the
accounting is silently broken in five distinct places.

- F70 (high): kernel death (OOM kill, crash, power loss) after the rail moved money
  (capture for generic adapters; pre-execution `authorize` for the in-tree prepaid
  X402/ACP adapters) but before `record_chio_receipt` commits leaves external funds
  moved with no receipt row and no stored rail reference. The durable
  `budget_mutation_events` log records exposure units and `hold_id` but not the
  payment `authorization_id`. Trigger: process death in that window. Effect: the payer
  is charged with no attested record. Impact: a direct breach of the receipt-log
  completeness guarantee the system exists to provide; recovery needs manual rail-side
  statement matching, and because `PaymentAdapter` requires no idempotency, no generic
  replay-based recovery can be built.
- F71 (medium): open budget holds have no sweeper. Trigger: crash between
  `authorize_budget_hold` and the post-execution reconcile. Effect: the hold stays
  `disposition='open'` and `total_cost_exposed` stays elevated forever. Impact: each
  crash permanently burns one invocation's worth of capacity per in-flight priced
  call; over months a multi-tenant kernel spuriously hits `BudgetExhausted`. Direction
  is fail-closed (under-spend), so this is availability erosion, not money loss.
- F68 (high): the settlement-observer outcome is discarded at
  `receipt_persistence.rs:185`. Trigger: any deployment wires a settlement hook and it
  returns `Retryable`/`Permanent` or errs for a money-bearing receipt. Effect: the
  outcome is dropped with no retry, no dead-letter row, no log, no metric. Impact:
  tool-server operators are silently never paid, and `chio settle status` reads tables
  no production code populates, so the loss is invisible to the tool built to detect
  it.
- F69 (medium): no production `SettlementHook`/`CreditEvaluatorHook` driver exists
  in-tree. Every implementation is test-only, so "settlement works" is unfalsifiable
  and any embedder inherits F68's silent-drop behavior.
- F72 (medium): `BudgetTree` skips the spend cap on currency mismatch, contradicting
  the module's own fail-closed claim. A EUR-denominated draft walks through USD caps
  with no deny and no warning.
- F73 (low): the durable EIP-3009 nonce store the docs reference does not exist; the
  in-memory store loses replay state on crash and wedges at capacity with no
  scheduled GC.
- F74 (low): `chio-metering::BudgetEnforcer` counters are process-local and reset to
  zero on restart, silently re-opening every tenant's full budget after each restart.

## Current behavior (verified 2026-07-04)

Money-path ordering in the kernel finalize path
(`crates/kernel/chio-kernel/src/kernel/validation.rs`):

1. Pre-execution the budget hold is durably debited. `authorize_budget_hold` is
   called at `validation.rs:784-796`; the sole durable pre-execution write of
   `total_cost_exposed`.
2. Pre-execution the payment rail is authorized. The authorize helper calls
   `adapter.authorize(&PaymentAuthorizeRequest { .. })` at `validation.rs:1274-1284`,
   returning a `PaymentAuthorization` held only in memory. For the prepaid adapters
   the real external HTTP call is in `authorize`
   (`crates/kernel/chio-kernel/src/payment.rs:287-310`) and `capture` is a local
   no-op returning `Settled` (`payment.rs:312-329`), so prepaid funds move here.
3. Post-execution the hold is reconciled and the rail captured/released.
   `reconcile_budget_charge` is called at `validation.rs:1000` (defined at
   `validation.rs:881-899`); then, at `validation.rs:1003-1025`, the generic path
   calls `adapter.release(&authorization.authorization_id, &request.request_id)`
   (line 1013) or `adapter.capture(&authorization.authorization_id, actual_cost,
   &charge.currency, &request.request_id)` (line 1015).
4. The financial metadata is built and the response constructed. `FinancialReceiptMetadata`
   is assembled at `validation.rs:1089-1108` and passed to
   `build_allow_response_with_metadata` at `validation.rs:1131`. Receipts with no
   payment adapter are stamped `ReceiptSettlement::settled()` at `validation.rs:1064`.
5. The signed receipt is persisted by `record_chio_receipt`
   (`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:164-187`).
   The final line is the F68 defect:

   ```rust
   let _settlement_status = self.run_settlement_observer(receipt);
   Ok(())
   ```

   The `SettlementObserverStatus` return is bound to `_settlement_status` and dropped.

The `PaymentAdapter` trait (`crates/kernel/chio-kernel/src/payment.rs:150-181`) has
the current signature (no idempotency requirement, no reconcile-query method):

```rust
pub trait PaymentAdapter: Send + Sync {
    fn authorize(&self, request: &PaymentAuthorizeRequest)
        -> Result<PaymentAuthorization, PaymentError>;
    fn capture(&self, authorization_id: &str, amount_units: u64, currency: &str,
        reference: &str) -> Result<PaymentResult, PaymentError>;
    fn release(&self, authorization_id: &str, reference: &str)
        -> Result<PaymentResult, PaymentError>;
    fn refund(&self, transaction_id: &str, amount_units: u64, currency: &str,
        reference: &str) -> Result<PaymentResult, PaymentError>;
}
```

A repo-wide grep for `payment`/`journal`/`pending_payment` in `chio-kernel` finds no
durable record of `authorization_id` before the receipt. The budget hold schema
(`crates/platform/chio-store-sqlite/src/budget_store/store.rs:36-49`) is:

```sql
CREATE TABLE IF NOT EXISTS budget_authorization_holds (
    hold_id TEXT PRIMARY KEY, capability_id TEXT NOT NULL, grant_index INTEGER NOT NULL,
    authorized_exposure_units INTEGER NOT NULL, remaining_exposure_units INTEGER NOT NULL,
    invocation_count_debited INTEGER NOT NULL, disposition TEXT NOT NULL,
    authority_id TEXT, lease_id TEXT, lease_epoch INTEGER,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
```

There is a `created_at` but no TTL/expiry column and no sweep query. `HoldDisposition`
(`crates/platform/chio-store-sqlite/src/budget_store/model.rs:4-9`) is
`{ Open, Released, Reversed, Reconciled }`. `BudgetMutationKind`
(`crates/kernel/chio-kernel/src/budget_store.rs:34-40`) is `{ IncrementInvocation,
AuthorizeExposure, ReverseExposure, ReleaseExposure, ReconcileSpend }`. No sweeper, no
open-hold listing, no CLI command exist across `chio-store-sqlite` and `chio-cli`.

The settlement machinery is fully built but unwired. `run_observer`
(`crates/kernel/chio-kernel/src/kernel/settlement_observer.rs:161-179`) returns
`SettlementObserverStatus { NotRegistered, Skipped { reason }, Observed { outcome },
HookFailed { error } }`. `classify_attempt`
(`crates/economy/chio-settle/src/retry.rs:123-154`) returns `RetryDecision { Retry {
attempt, backoff }, DeadLetter { reason }, Skip { reason } }` under `RetryPolicy`
(defaults `max_retries=5`, `initial_backoff_ms=250`, `backoff_multiplier=2`,
`backoff_cap_ms=60_000`). `SqliteDeadLetterStore`
(`crates/platform/chio-store-sqlite/src/dead_letters.rs:55-205`) has
`insert`/`get`/`list`/`clear` over `settle_dead_letters` but zero callers outside its
own tests. The kernel doc at `construction.rs:483` and the crate doc at
`crates/economy/chio-settle/src/hook.rs:7-9` both claim the observer slot "routes it
to the retry/dead-letter machinery"; nothing does. The CLI reads
`settle_dead_letters`/`iou_envelope`/`settlement_reconciliations`
(`crates/products/chio-cli/src/settle.rs:89-99`, `181-196`, `260-283`) but only its
own tests populate those tables (the INSERTs at `settle.rs:339-360`).

`BudgetTree::evaluate` skips the spend cap on currency mismatch
(`crates/economy/chio-metering/src/budget_hierarchy.rs:613-637`):

```rust
if let Some(cap) = limits.max_spend_units {
    let currency_matches = match (&limits.currency, &draft.currency) {
        (Some(a), Some(b)) => a == b,
        _ => false, // "mismatched currency means we skip"
    };
    if currency_matches && projected.spend_units > cap { /* deny */ }
}
```

The module doc at `budget_hierarchy.rs:9` claims "the tree renders a fail-closed
`BudgetDecision`". `BudgetDenyReason`
(`budget_hierarchy.rs:334-364`) has `{ NodeDisabled, DimensionExceeded, WindowExpired,
UnknownNode }`, no currency variant.

The only `Eip3009NonceStore` implementation
(`crates/economy/chio-settle/src/payments.rs:406`) is `InMemoryEip3009NonceStore`
(`Mutex<HashMap>`); the doc at `payments.rs:366-371` claims a SQLite store "wired by
default" that does not exist. At `DEFAULT_MAX_EIP3009_NONCE_ENTRIES = 65_536`
(`payments.rs:284`) the record path returns `SettlementError::InvalidBinding`
(`payments.rs:426-432`) and `gc_expired` (`payments.rs:437-442`) has no scheduler.

`BudgetEnforcer` (`crates/economy/chio-metering/src/budget.rs:78-89`) holds a plain
`u64 total_spent` and three `HashMap`s zeroed in `new()` (`budget.rs:91-101`);
`record()` (`budget.rs:167-181`) mutates in memory only. No persistence seam.

## Design

The money path gains one durable state machine (`payment_journal`), one recovery
sweep, and one routing consumer, plus four smaller fail-closed corrections. All new
code uses `?` or explicit typed-error `match`; no `unwrap`/`expect`. Fail-closed is the
posture throughout: on any ambiguity the change denies, dead-letters, or raises a loud
operator incident rather than silently proceeding.

### F70: durable payment journal + idempotent adapter contract

New table in the budget-store database (co-located with the holds so the pre-execution
hold write and the journal write share one `TransactionBehavior::Immediate`
transaction), added in `crates/platform/chio-store-sqlite/src/budget_store/store.rs`
beside the `budget_authorization_holds` DDL:

```sql
CREATE TABLE IF NOT EXISTS payment_journal (
    request_id        TEXT PRIMARY KEY,
    capability_id     TEXT NOT NULL,
    grant_index       INTEGER NOT NULL,
    hold_id           TEXT,
    rail              TEXT NOT NULL,          -- adapter id, known before authorize
    authorization_id  TEXT,                   -- attached after authorize returns
    transaction_id    TEXT,                   -- attached after capture/refund returns
    amount_units      INTEGER NOT NULL,       -- preauthorized (hold) amount
    settle_action     TEXT,                   -- capture|release, stamped before Settling
    settle_amount_units INTEGER,              -- exact capture amount; NULL for release
    currency          TEXT NOT NULL,
    state             TEXT NOT NULL,          -- see PaymentJournalState
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payment_journal_state ON payment_journal(state);
```

New types in `crates/kernel/chio-kernel/src/payment.rs` (kernel-owned, mirrored into
the store crate):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentJournalState {
    /// Row written with the budget hold, before adapter.authorize.
    HoldPlaced,
    /// adapter.authorize returned; authorization_id is set.
    Authorized,
    /// About to call capture/release; the rail may move money next.
    Settling,
    /// capture returned Settled / release returned Released.
    Settled,
    /// Receipt persisted; terminal success.
    Closed,
    /// Boot reconcile could not settle or determine outcome; operator incident.
    ReconcileFailed,
}

/// Terminal action chosen before entering `Settling`: the rail call boot
/// reconciliation must replay for a `Settling` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentSettleAction {
    /// Capture the recorded `amount_units` from the hold.
    Capture,
    /// Release the whole hold without capturing.
    Release,
}

/// The committed settle decision, stamped atomically with the advance to
/// `Settling` so reconciliation replays the exact operation rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentSettleIntent {
    pub action: PaymentSettleAction,
    /// Exact capture amount for `Capture`; `None` for `Release`.
    pub amount_units: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentJournalRecord {
    pub request_id: String,
    pub capability_id: String,
    pub grant_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_id: Option<String>,
    pub rail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    pub amount_units: u64,
    /// Terminal action stamped before entering `Settling`. None until step 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_action: Option<PaymentSettleAction>,
    /// Exact capture amount recorded with `Capture`; None for `Release`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_amount_units: Option<u64>,
    pub currency: String,
    pub state: PaymentJournalState,
    pub created_at_unix_ms: u64,
}
```

New `BudgetStore` methods (`crates/kernel/chio-kernel/src/budget_store.rs`, defaulted
so non-SQLite stores stay compilable and fail closed if a monetary call reaches them):

```rust
/// Insert a fresh journal row in `HoldPlaced`. Collides fail-closed on a reused
/// request_id (INSERT ... ON CONFLICT(request_id) DO NOTHING; zero rows -> Conflict).
fn record_payment_journal(&self, _entry: &PaymentJournalRecord)
    -> Result<(), BudgetStoreError> {
    Err(BudgetStoreError::Invariant(
        "payment journal is not supported by this budget store".to_string(),
    ))
}

/// Compare-and-set state advance. `expected` must match the current row state or the
/// call returns Conflict (fail-closed); optional fields are attached when present. When
/// advancing to `Settling` the caller MUST pass `settle` (the committed action and, for
/// a capture, the exact amount) so boot reconciliation can replay the exact operation;
/// the store stamps `settle_action`/`settle_amount_units` atomically with the state
/// change. `settle` is None for every other transition.
fn advance_payment_journal(&self, _request_id: &str, _expected: PaymentJournalState,
    _next: PaymentJournalState, _authorization_id: Option<&str>,
    _transaction_id: Option<&str>, _settle: Option<PaymentSettleIntent>)
    -> Result<(), BudgetStoreError> {
    Err(BudgetStoreError::Invariant(
        "payment journal is not supported by this budget store".to_string(),
    ))
}

/// Move the row to Closed. Idempotent: already-Closed returns Ok(false).
fn close_payment_journal(&self, _request_id: &str) -> Result<bool, BudgetStoreError> {
    Err(BudgetStoreError::Invariant(
        "payment journal is not supported by this budget store".to_string(),
    ))
}

/// Rows in a non-terminal state older than `older_than_unix_ms`, for boot reconcile.
/// Fail closed like the write-side journal defaults above: a store that persists
/// `HoldPlaced`/`Settling` rows but leaves listing unimplemented MUST NOT silently
/// report zero incomplete payments, because that would skip boot reconciliation
/// entirely and strand in-flight holds. An unsupported listing is an explicit,
/// operator-visible error, never an empty success.
fn list_incomplete_payment_journal(&self, _older_than_unix_ms: u64)
    -> Result<Vec<PaymentJournalRecord>, BudgetStoreError> {
    Err(BudgetStoreError::Invariant(
        "payment journal listing is not supported by this budget store".to_string(),
    ))
}
```

Kernel control-flow changes in `validation.rs`, all keyed on `request.request_id`:

1. Before `adapter.authorize` at `validation.rs:1274`, write the journal row with
   `state = HoldPlaced`, `rail = adapter.rail_id()`, `authorization_id = None`. The
   kernel sets `PaymentAuthorizeRequest.reference` (payment.rs:91) to this same
   `request_id`, so authorize's idempotency key is durable before the external call
   and the HoldPlaced row is recoverable through `settlement_state(request_id, None)`
   if the process dies before step 2.
   Atomicity note: every SQLite `BudgetStore` method opens its own
   `TransactionBehavior::Immediate` transaction
   (`budget_store/trait_impl.rs`), so calling two trait methods inside one
   `with_budget_store(|store| ...)` closure yields two transactions, not one. To
   make the hold and journal genuinely atomic, `BudgetAuthorizeHoldRequest`
   (`crates/kernel/chio-kernel/src/budget_store.rs:176`, which already carries the
   optional `hold_id`/`event_id`/`authority`) gains an optional
   `payment_journal: Option<PaymentJournalRecord>` field, and the SQLite
   `authorize_budget_hold` inserts the journal row inside the same transaction as
   the hold write. `record_payment_journal` remains the standalone insert for
   recovery tooling and tests.
2. After `adapter.authorize` returns `PaymentAuthorization`, call
   `advance_payment_journal(request_id, HoldPlaced, Authorized,
   Some(&auth.authorization_id), None, None)` (no settle intent yet).
3. Before `adapter.capture`/`adapter.release` at `validation.rs:1013-1015`, advance to
   `Settling` PASSING the terminal settle intent
   (`Some(PaymentSettleIntent { action, amount_units })`): `Capture` with the exact
   post-execution cost (which may differ from the preauthorized `amount_units`), or
   `Release` with `None`. The intended rail call and its amount are thus durable
   BEFORE any money can move, so a crash inside the rail call is replayable without
   guessing. After it returns `PaymentResult`, advance to `Settled` attaching
   `transaction_id`.
4. After `record_chio_receipt` commits the signed receipt, call
   `close_payment_journal(request_id)` (best-effort-durable). A crash between the
   receipt commit and the close leaves a `Settled` row that boot reconcile closes,
   because the matching attested receipt exists.

The `PaymentAdapter` trait is amended to make replay-based recovery sound. Three
additions (the idempotency contract plus two defaulted methods, both fail-closed):

```rust
/// Side-effect-free snapshot of the rail's view of a prior authorization, keyed on
/// the durable `reference`. Distinct from `PaymentResult` because the HoldPlaced
/// crash-window query MUST be able to return the rail-assigned `authorization_id`
/// even though no funds have moved and no `transaction_id` exists yet; `PaymentResult`
/// (payment.rs:19-25) carries only `transaction_id`/`settlement_status`/`metadata` and
/// cannot convey the id, which would force adapters to smuggle it through ad hoc
/// metadata and leave reconciliation unable to call `release`/`capture` reliably.
pub enum RailSettlementState {
    /// The rail has no hold or settlement for this reference: `authorize` never took
    /// effect. Reconciliation reverses the local budget hold and closes the journal.
    NoAuthorization,
    /// A hold exists but no funds have moved. Carries the rail-assigned
    /// `authorization_id` so reconciliation can persist it (advance the journal to
    /// `Authorized`) and drive the idempotent `release`/`capture` APIs.
    Held { authorization_id: String },
    /// Funds already moved on the rail. Carries the rail-assigned `authorization_id`
    /// and the settled `PaymentResult` so reconciliation can record the id and emit a
    /// signed receipt for the already-moved amount.
    Settled { authorization_id: String, result: PaymentResult },
}

pub trait PaymentAdapter: Send + Sync {
    // ... authorize / capture / release / refund unchanged in signature ...

    /// CONTRACT: authorize MUST be idempotent keyed on `request.reference`
    /// (payment.rs:91), which the kernel sets to the durable `request_id` written
    /// into the journal BEFORE the call. A repeated authorize with the same
    /// reference returns the same authorization and places AT MOST ONE rail-side
    /// hold. This closes the HoldPlaced crash window: if the process dies after
    /// authorize succeeds but before the post-call journal advance (step 2 below),
    /// no `authorization_id` is durable yet, but reconciliation can still discover
    /// or release the hold via `settlement_state(request_id, None)` because the
    /// reference is durable.

    /// CONTRACT: capture and release MUST be idempotent keyed on
    /// (authorization_id, reference). A repeated call with the same key returns an
    /// equivalent PaymentResult and moves money AT MOST ONCE. Boot reconciliation
    /// relies on this to replay a Settling journal row without double-charging.

    /// Stable rail identifier recorded in the payment journal before authorize
    /// runs (in-tree: "x402", "acp"). Needed because the kernel holds only a
    /// boxed trait object (set_payment_adapter, construction.rs:429) with no
    /// other name for the rail. Defaulted so third-party adapters compile; an
    /// "unspecified" rail makes boot reconciliation fail closed to
    /// ReconcileFailed rather than guessing which rail to query.
    fn rail_id(&self) -> &'static str {
        "unspecified"
    }

    /// Query the current rail-side settlement state for a prior authorization WITHOUT
    /// moving funds. Idempotent and side-effect-free. Keyed on `reference` (the durable
    /// `request_id` written into the journal before authorize), so it stays answerable
    /// in the HoldPlaced crash window where no `authorization_id` is durable yet;
    /// `authorization_id` is an optional refinement passed once known. Returns a
    /// `RailSettlementState` that explicitly carries the rail-assigned `authorization_id`
    /// when a hold or settlement exists, so boot reconciliation can record it and act on
    /// it (persist, release, or capture) instead of discarding it or relying on adapters
    /// to hide it in `PaymentResult.metadata`. Defaulted to `Unavailable` so an adapter
    /// that cannot answer forces a fail-closed operator incident rather than a silent
    /// close during reconciliation.
    fn settlement_state(&self, reference: &str, authorization_id: Option<&str>)
        -> Result<RailSettlementState, PaymentError> {
        let _ = (reference, authorization_id);
        Err(PaymentError::Unavailable(
            "settlement_state query not implemented by this adapter".to_string(),
        ))
    }
}
```

Boot reconciliation (registered into RFC-0003's boot recovery orchestration and
serving RFC-0003's `MonetaryReconciled` resolution) iterates
`list_incomplete_payment_journal(now - horizon)` and, per row, is deterministic (no
discretion, mirroring ADR-0015 D3/D5):

- `HoldPlaced`: authorize may or may not have fired, and no `authorization_id` is
  durable. Query `settlement_state(request_id, None)` by the durable reference and match
  the returned `RailSettlementState`: `NoAuthorization` closes the journal and reverses
  the budget hold (funds never moved); `Held { authorization_id }` records the returned
  `authorization_id`, advances the journal to `Authorized`, and completes per the
  `Authorized` state below; `Settled { authorization_id, result }` records the id and
  completes per the `Settled` state below (the money already moved). An `Unavailable`
  error is `ReconcileFailed`, never a silent close. Because the id is carried by the
  return type, recovery never has to guess or reconstruct it from ad hoc metadata.
- `Authorized`: authorize succeeded but no terminal action was ever committed (the crash
  predates step 3, so `settle_action` is NULL). No capture amount was chosen, so the only
  sound, price-free completion is to `release` the hold (idempotent) and close; funds
  were only held.
- `Settling`: a terminal action IS durable. Replay exactly the recorded `settle_action`
  and `settle_amount_units` (idempotent by the amended contract): `Capture` re-captures
  the recorded amount, `Release` releases the hold. This is a predeclared, price-free
  terminal state (ADR-0015 D2): it never selects a new amount, only completes the
  committed one. A `Settling` row missing its `settle_action` is a corrupt row and is
  `ReconcileFailed`, never a guessed capture or release.
- `Settled`: the money moved. If a receipt with the same `request_id` exists, close
  (attested). Otherwise emit a signed reconciliation receipt for the already-moved
  amount and close.
- Any adapter error or `settlement_state` returning `Unavailable`: set
  `ReconcileFailed` and raise an operator incident. Never silently close.

### F71: open-hold sweeper

Extend `HoldDisposition` (`budget_store/model.rs:4-9`) with `Expired` (`as_str` ->
`"expired"`) and `BudgetMutationKind` (`kernel/budget_store.rs:34-40`) with `ExpireHold`
(`as_str` -> `"expire_hold"`). Add two `BudgetStore` methods:

```rust
/// Open holds whose created_at is older than the horizon, oldest first.
fn list_open_holds_older_than(&self, older_than_unix_ms: u64, limit: usize)
    -> Result<Vec<OpenHoldSummary>, BudgetStoreError>;

/// Release the remaining exposure of an open hold, marking it Expired and writing a
/// BudgetMutationKind::ExpireHold event. Idempotent: a non-open hold returns Ok(false).
fn expire_open_hold(&self, hold_id: &str) -> Result<bool, BudgetStoreError>;
```

`OpenHoldSummary` is a new read-model struct carrying `hold_id`, `capability_id`,
`grant_index`, `remaining_exposure_units`, and `created_at_unix_ms` (a projection of
the `budget_authorization_holds` columns).

`expire_open_hold` runs one `Immediate` transaction that subtracts
`remaining_exposure_units` from `capability_grant_budgets.total_cost_exposed`, sets the
hold `disposition = 'expired'`, and appends the `expire_hold` mutation event. It never
touches `total_cost_realized_spend`, so an expired hold releases capacity without
recording spend (fail-closed under-spend, consistent with ADR-0006's monotone
`total_cost_charged`).

A kernel sweep task (boot-once, then periodic on `hold_sweep_interval`, default
`300s`) calls `list_open_holds_older_than(now - hold_expiry_horizon, batch)` and
`expire_open_hold` per row. `hold_expiry_horizon` defaults to `3600s`: generously above
any legitimate in-flight call, so the sweeper only ever collects true orphans. A gauge
metric `chio_budget_open_holds` and a counter `chio_budget_holds_expired_total`
(both declared in `chio-metrics-spec` and exported through the kernel's Prometheus
text exposition, per the F68 note) make the leak visible, and the CLI gains `chio budget holds list` and `chio budget holds release
<hold-id>` over the same two methods.

### F68: route the settlement-observer outcome

Replace the discard at `receipt_persistence.rs:185` with a routing call, keeping the
current lock scope (the observer already runs outside the receipt-store write lock):

```rust
let status = self.run_settlement_observer(receipt);
self.route_settlement_observer_status(receipt, &status);
Ok(())
```

`route_settlement_observer_status` (new kernel method) is fail-loud and fail-closed:

```rust
fn route_settlement_observer_status(&self, receipt: &ChioReceipt,
    status: &SettlementObserverStatus) {
    use SettlementObserverStatus as S;
    let (outcome_reason, retryable) = match status {
        S::NotRegistered | S::Skipped { .. } => return, // steady state, nothing owed
        S::Observed { outcome } => match self.classify_and_persist(receipt, outcome) {
            Ok(()) => return,
            Err(error) => (error.to_string(), true),
        },
        S::HookFailed { error } => (error.clone(), true),
    };
    // Loud until the retry loop drains it: warn + metric are the minimum viable fix.
    warn!(receipt_id = %receipt.id, retryable, reason = %outcome_reason,
        "settlement outcome unresolved");
    self.settlement_unresolved_total.fetch_add(1, Ordering::Relaxed);
}
```

The counter is a kernel-owned `AtomicU64` exported through the existing Prometheus
text exposition under a new `CHIO_SETTLEMENT_UNRESOLVED_TOTAL` name declared in
`chio-metrics-spec`, following the pattern of `CHIO_SIGNING_QUEUE_BLOCK_TOTAL` and
`signing_queue_block_total()` (`crates/kernel/chio-kernel/src/kernel/signing_task.rs:163-166`).
The kernel does not link a `metrics` crate facade; new metric families are declared
in `chio-metrics-spec` and wired into the `/metrics` exposition
(`kernel/src/observability/metrics.rs`).

`classify_and_persist` reads a persisted attempt counter for `receipt.id`, runs
`classify_attempt(&self.settlement_retry_policy, attempt, outcome)`, and then:

- `RetryDecision::Skip`: clear any attempt row and return.
- `RetryDecision::Retry { attempt, backoff }`: upsert the attempt row with the new
  attempt count and `next_visible_at = now + backoff` for the driver (F69) to pick up.
- `RetryDecision::DeadLetter { reason }`: build a `DeadLetterRecord::new(receipt.id,
  receipt.timestamp, attempts, reason)` and `SqliteDeadLetterStore::insert` it; on the
  `Conflict` case (a different row already exists) surface a warn and metric.

The attempt counter is a new table (budget/receipt-store-adjacent):

```sql
CREATE TABLE IF NOT EXISTS settle_attempts (
    receipt_id      TEXT PRIMARY KEY,
    finalized_at    INTEGER NOT NULL,
    attempts        INTEGER NOT NULL,
    next_visible_at INTEGER NOT NULL,
    last_reason     TEXT,
    updated_at      INTEGER NOT NULL
);
```

Even before the full retry driver (F69) exists, this closes F68's silent drop: every
unresolved money-bearing receipt is now a `warn!`, a metric increment, and either a
`settle_attempts` row or a `settle_dead_letters` row.

### F69: production settlement driver seam

Specify the intended driver so `chio settle status` reports over tables real code
writes. Ship a reference `OpsSettlementHook` in `chio-settle` implementing
`SettlementHook` over `chio-settle/ops.rs`, and a `SettlementRuntime` task that:

- drains `settle_attempts WHERE next_visible_at <= now` on a tick,
- re-invokes the hook, re-runs `classify_and_persist`,
- on `Accepted` writes the `iou_envelope` and `settlement_reconciliations` rows the CLI
  already reads, and
- is wired into the CLI runtime behind a config flag `settlement.driver = { none, ops }`
  (default `none`, so nothing changes until an operator opts in).

Add an end-to-end test exercising receipt -> IOU -> retry -> dead-letter against a real
kernel. Until the driver ships, correct the two misleading docs: `construction.rs:483`
and `hook.rs:7-9` must say routing to retry/dead-letter is wired only when a driver is
installed, not unconditionally. This finding is not on the request-serving path
(`production_path=false`); this RFC specifies the seam and the doc fix, and the driver
implementation is a follow-up tracked in the wave-3 program.

### F72: fail-closed currency mismatch in BudgetTree

Add a `BudgetDenyReason` variant and deny instead of skip. In `budget_hierarchy.rs`:

```rust
/// A spend cap exists but the draft currency is absent or differs from the node's.
/// Fail-closed: an uncomparable spend cap denies rather than being skipped.
CurrencyMismatch {
    node: BudgetNodeId,
    node_currency: Option<String>,
    draft_currency: Option<String>,
},
```

Replace the skip at `budget_hierarchy.rs:613-637`:

```rust
if let Some(cap) = limits.max_spend_units {
    match (&limits.currency, &draft.currency) {
        (Some(node_c), Some(draft_c)) if node_c == draft_c => {
            if projected.spend_units > cap { /* DimensionExceeded as today */ }
        }
        _ => {
            offender = Some((idx, BudgetDenyReason::CurrencyMismatch {
                node: node_id.clone(),
                node_currency: limits.currency.clone(),
                draft_currency: draft.currency.clone(),
            }));
        }
    }
}
```

This realizes ADR-0006's stated fail-closed stance on cross-currency comparison at the
tree layer (the ADR notes the kernel per-invocation check already fails a USD-vs-EUR
mismatch; this closes the same gap in the hierarchy). Tree-load validation may
additionally reject a tree whose nodes disagree on currency, so the mismatch is caught
at config time; the runtime deny remains as the fail-closed backstop.

### F73: durable SQLite EIP-3009 nonce store

Add `SqliteEip3009NonceStore` in `crates/platform/chio-store-sqlite` implementing the
existing `chio_settle::Eip3009NonceStore` trait (`payments.rs:317-344`) over:

```sql
CREATE TABLE IF NOT EXISTS eip3009_nonces (
    from_address TEXT NOT NULL,
    nonce_key    TEXT NOT NULL,
    retain_until INTEGER NOT NULL,
    PRIMARY KEY (from_address, nonce_key)
);
CREATE INDEX IF NOT EXISTS idx_eip3009_nonces_retain_until ON eip3009_nonces(retain_until);
```

`record_if_fresh` is an `Immediate`-transaction `INSERT ... ON CONFLICT DO NOTHING`
returning `Fresh`/`Replayed` from the affected-row count (atomic per EIP-3009's
single-use requirement); it lowercases key components exactly as
`canonicalize_nonce_key_component` (`payments.rs:357-364`) does. It does NOT prune: the
trait contract (`payments.rs:311-316`) makes `gc_expired` the sole entry point that
drops entries so replay decisions stay decoupled from the wall clock, and
`record_if_fresh` has no `now` argument to prune against. `gc_expired` is a
`DELETE ... WHERE retain_until < ?`. To defuse the capacity wedge without a scheduler and
without breaking that contract, the caller drives GC explicitly on the `now`-bearing
path: the settlement verifier already computes `now` for the authorization validity
window, so it calls `gc_expired(now)` immediately BEFORE `record_if_fresh` whenever a
cheap `len()` probe crosses a high-water mark (7/8 of
`DEFAULT_MAX_EIP3009_NONCE_ENTRIES`). Pruning thus stays on the explicit, now-driven GC
path and never inside insertion. The lane's future wiring is gated on this durable
store, and the stale `payments.rs:366-371` doc is corrected to name it.

### F74: BudgetEnforcer durability caveat + snapshot seam

`BudgetEnforcer` has no production consumer (the sole external `chio-metering` user,
`crates/guards/chio-data-guards/src/warehouse_cost_guard.rs:55`, imports only
`CostDimension`), so the minimum viable fix is a loud caveat plus an explicit
snapshot/restore seam:

```rust
/// WARNING: counters are process-local and reset to zero on restart. This type does
/// NOT persist cumulative spend; a restart re-opens the full budget. For durable
/// enforcement use the kernel `BudgetStore` (crates/kernel/chio-kernel/src/budget_store.rs).
/// Callers requiring cross-restart continuity MUST snapshot and restore explicitly.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudgetEnforcerSnapshot {
    pub total_spent: u64,
    pub session_spent: HashMap<String, u64>,
    pub agent_spent: HashMap<String, u64>,
    pub tool_spent: HashMap<String, u64>,
}

impl BudgetEnforcer {
    #[must_use]
    pub fn snapshot(&self) -> BudgetEnforcerSnapshot { /* clone counters */ }

    #[must_use]
    pub fn from_snapshot(policy: BudgetPolicy, snapshot: BudgetEnforcerSnapshot) -> Self { /* seed */ }
}
```

The rustdoc caveat is the trap-defusing one-liner; the snapshot seam lets any future
adopter persist and restore counters instead of silently losing them.

### Error taxonomy (typed, fail-closed)

- `BudgetStoreError::Invariant` (existing) carries the unsupported-store and
  compare-and-set-mismatch cases for the payment journal and sweeper; a mismatched
  `advance_payment_journal` expected-state is a `Conflict`-shaped invariant, aborting
  fail-closed.
- `DeadLetterStoreError::{ Backend, Conflict }` (existing,
  `dead_letters.rs:42-50`) already covers dead-letter insert failures; the routing
  consumer maps a `Conflict` to a warn+metric, never a silent drop.
- `PaymentError::Unavailable` (existing, `payment.rs:192`) is the fail-closed return
  from the defaulted `settlement_state`, forcing a `ReconcileFailed` incident rather
  than a wrong close.
- `BudgetDenyReason::CurrencyMismatch` (new) is the fail-closed tree outcome.
- `SettlementError::InvalidBinding` (existing) remains the EIP-3009 replay/capacity
  return; the durable store preserves those semantics.

### Crates, dirs, LOC, CI tier

- `crates/platform/chio-store-sqlite`: `payment_journal` + `settle_attempts` +
  `eip3009_nonces` DDL and methods, `SqliteEip3009NonceStore`, `HoldDisposition::Expired`,
  sweeper queries, dead-letter/attempt wiring. ~520 LOC + ~360 LOC tests.
- `crates/kernel/chio-kernel`: `PaymentJournalRecord`/`PaymentJournalState`, journal
  and sweeper trait methods, `validation.rs` wiring, `route_settlement_observer_status`,
  `classify_and_persist`, `BudgetMutationKind::ExpireHold`, config, boot hooks. ~430 LOC
  + ~320 LOC tests.
- `crates/economy/chio-metering`: `BudgetDenyReason::CurrencyMismatch`, evaluate change,
  `BudgetEnforcerSnapshot`. ~90 LOC + ~120 LOC tests.
- `crates/economy/chio-settle`: `PaymentAdapter` doc/`settlement_state` amendment lives
  in the kernel crate; `OpsSettlementHook` + `SettlementRuntime` driver seam. ~260 LOC
  + ~200 LOC tests.
- `crates/products/chio-cli`: `chio budget holds list/release`, `settlement.driver`
  flag. ~120 LOC + ~90 LOC tests.
- `crates/observability/chio-metrics-spec`: descriptor declarations for
  `CHIO_SETTLEMENT_UNRESOLVED_TOTAL`, `CHIO_BUDGET_OPEN_HOLDS`, and
  `CHIO_BUDGET_HOLDS_EXPIRED_TOTAL`. ~25 LOC.
- No new crate. Unit and property tests run on the PR gate (well under a minute).
  Crash/kill-injection soak (SIGKILL between authorize and receipt commit; between
  authorize_budget_hold and reconcile) runs nightly in the load-chaos program, budgeted
  at roughly 15-25 minutes. The full power-loss and multi-restart budget-continuity
  simulation runs weekly.

## Wire, schema, and receipt impact

- Signed receipt payloads are unchanged. Settlement status stays the advisory
  `FinancialReceiptMetadata::settlement_status` field ADR-0006's no-refund model
  already defines; the journal and reconciliation never rewrite a signed receipt.
- New non-audit SQLite tables: `payment_journal`, `settle_attempts`, `eip3009_nonces`,
  all created idempotently at store open (`CREATE TABLE IF NOT EXISTS`). The existing
  `settle_dead_letters`, `iou_envelope`, and `settlement_reconciliations` tables are
  now populated by production code (F68/F69), not only tests.
- `PaymentJournalRecord`, `DeadLetterRecord` (existing, schema `chio.settle.dead-letter.v1`),
  and any reconciliation report serialize as RFC 8785 canonical JSON, consistent with
  the canonical-JSON `parameter_hash` and dead-letter row bytes already in use.
- `BudgetDenyReason` gains a `CurrencyMismatch` variant. It is config-as-data JSON
  (serde `tag = "reason"`, snake_case); additive, older readers that do not expect it
  fail closed on the deny rather than silently allowing.
- New `BudgetMutationKind::ExpireHold` (`"expire_hold"`) and `HoldDisposition::Expired`
  (`"expired"`) are additive string enum values in the durable budget log.

## Migration and compatibility

- Backward compatible: every new table and enum value is additive; older binaries
  ignore the tables and treat unknown mutation kinds/dispositions as opaque. Newer
  binaries create the tables on open.
- No data migration: there are no historical journal, attempt, or nonce rows. Existing
  holds without the sweeper simply become eligible for the first sweep once the new
  binary runs; the horizon default (`3600s`) ensures no in-flight hold is collected.
- Staged rollout. The payment journal is the money-path specialization of RFC-0003's
  `DispatchIntentJournalMode`; enable it with the `Monetary` class first (highest
  consequence), gated behind the same config. The F68 routing consumer ships enabled
  (it only adds logging, metrics, and dead-letter rows). The F69 driver ships behind
  `settlement.driver = none` by default. The durable EIP-3009 store becomes the wired
  default only once the lane is exercised.
- Operator-visible behavior changes to document in release notes: newly surfaced
  dead-letter rows and `ReconcileFailed` incidents are "recovery working", not "new
  fault"; the hold sweeper releasing capacity is expected, not a budget bug.

## Test and verification plan

- Unit: journal insert collision on a reused `request_id` fails closed;
  `advance_payment_journal` with a wrong `expected` state returns `Conflict`;
  `expire_open_hold` on a non-open hold is idempotent; `close_payment_journal` is
  idempotent; `settlement_state` default returns `Unavailable`.
- Property: for a random interleaving of authorize/capture/release/crash, after boot
  reconcile every `request_id` resolves to exactly one of `{ Closed with attested
  receipt, Closed with reconciliation receipt, ReconcileFailed incident }`, never a
  silent non-terminal row and never a double capture (idempotency witness).
- Property (F72): for random node/draft currency pairs, `BudgetTree::evaluate` never
  returns `Allow` when a node has `max_spend_units` and the draft currency is absent or
  differs.
- Loom: model the settlement routing consumer with concurrent `Observed`/`HookFailed`
  and a driver drain, asserting no lost attempt row and no double dead-letter, reusing
  the dead-letter idempotency (`dead_letters.rs` byte-identical replay).
- Crash/chaos (load-chaos program): the specific test that proves F70 is
  `payment_journal_crash_reconciles_every_capture` - SIGKILL the kernel after prepaid
  `authorize` (`validation.rs:1274`) and after `capture` (`validation.rs:1015`),
  restart, run reconcile, and assert every killed request ends attested-or-incident,
  never silent. F71's proof is `open_hold_sweeper_releases_orphaned_capacity` - SIGKILL
  between `authorize_budget_hold` and reconcile, restart, sweep, assert
  `total_cost_exposed` returns to its pre-call value and a `expire_hold` event exists.
- Soak: sustained priced load with periodic kills; assert `chio_budget_open_holds`
  returns to zero after each sweep, `settle_attempts` drains, and no journal row is
  stuck non-terminal.
- Formal-methods tie-in: the money-path invariant `moved_funds(request_id) ->
  eventually(attested_receipt XOR reconciliation_incident)` is stated as a liveness
  predicate in the formal-methods plan; the property and crash tests are its executable
  witnesses. It composes with RFC-0003's `receipt XOR open_intent` safety predicate.

## Acceptance criteria

- Killing the kernel between rail-money-movement and receipt commit and restarting
  yields, for every in-flight priced request, exactly one durable terminal outcome: an
  attested receipt, a reconciliation receipt, or a `ReconcileFailed` operator incident
  naming the `rail` and `authorization_id`. Never a charge with no record.
- After a clean run's reconcile, `list_incomplete_payment_journal` returns empty and
  `chio_budget_open_holds == 0`.
- An open budget hold older than `hold_expiry_horizon` is swept to `disposition='expired'`
  with a matching `expire_hold` mutation event, and `total_cost_exposed` drops by exactly
  the released remainder (no realized spend recorded).
- A settlement hook returning `Retryable`/`Permanent`/error for a money-bearing receipt
  produces a `settle_attempts` or `settle_dead_letters` row plus a warn and a metric;
  `chio settle status` reports it. Nothing is dropped at `receipt_persistence.rs:185`.
- `BudgetTree::evaluate` returns `Deny(CurrencyMismatch)` for a spend-capped node whose
  currency is absent or differs from the draft; no `Allow` with unlimited spend.
- The EIP-3009 nonce store survives a restart (a previously recorded `(from, nonce)`
  reads `Replayed`) and cannot wedge at capacity without an operator.
- `BudgetEnforcer` carries the durability caveat and a working `snapshot`/`from_snapshot`
  round-trip.

## Risks and alternatives

- Added latency on priced calls: one extra durable write before authorize and one
  compare-and-set per state transition. Each rides the existing budget-store `Immediate`
  transaction and is dwarfed by the external rail call; the `Monetary`-class gate bounds
  the cost, and the soak measures it before the journal becomes default.
- Idempotency is a contract, not enforcement: the amended `PaymentAdapter` doc requires
  idempotent capture/release, but an adapter that violates it could double-charge on
  replay. Mitigation: reconciliation prefers the side-effect-free `settlement_state`
  query and only replays capture/release for adapters that declare idempotency; the
  in-tree prepaid adapters are already idempotent (capture is a local no-op).
- Sweeper aggressiveness: too short a horizon could reclaim a legitimately slow
  in-flight hold. Mitigation: the `3600s` default is far above any real call, the sweep
  only touches `disposition='open'`, and reclaiming is fail-closed under-spend (the
  worst case is a spuriously denied retry, not overspend).
- Alternative considered and rejected: putting the payment journal in the receipt-store
  database beside RFC-0003's `chio_dispatch_intents`. Rejected because the earliest
  durable pre-execution write is the budget hold, and co-locating lets the hold and
  journal commit in one transaction; RFC-0003's generic intent remains the complementary
  `receipt XOR open_intent` record.
- Alternative considered and rejected: reversing the budget charge automatically on
  settlement failure. Rejected because ADR-0006's no-refund model makes
  `total_cost_charged` monotone; the journal records and reconciles the rail movement
  without inventing a refund the kernel does not own.
- Alternative considered and rejected: a background thread that blind-retries dropped
  settlement outcomes without a persisted attempt counter. Rejected because it cannot
  survive restart and cannot bound retries; the `settle_attempts` table plus
  `classify_attempt` gives a durable, bounded envelope.

## Rollout and sequencing

1. RFC-0003 lands first: it provides the boot recovery orchestration, the operator
   incident sink, and the `rail`/`rail_authorization_id` substrate plus the
   `MonetaryReconciled` resolution that this RFC's reconciler satisfies.
2. F72 and the F68 routing consumer land next: both are small, self-contained,
   fail-closed corrections with no dependency on the journal.
3. The payment journal (F70) + hold sweeper (F71) land together, gated behind the
   `Monetary` journal mode, promoted to default after the nightly kill-injection soak is
   green.
4. The durable EIP-3009 store (F73) and the `BudgetEnforcer` caveat/snapshot (F74) land
   as independent hardening; the EIP-3009 store becomes the wired default only when the
   lane is exercised.
5. The F69 production driver (`OpsSettlementHook` + `SettlementRuntime`) is the final
   step, behind `settlement.driver = ops`, turning the F68 attempt rows into real IOU
   and reconciliation rows.
