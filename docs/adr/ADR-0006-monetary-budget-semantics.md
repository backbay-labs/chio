# ADR-0006: Monetary Budget Semantics

> Superseded in part by ADR-0016: the "monotonic, no-refund" exposure text is
> replaced by the authorize-then-reconcile hold lifecycle (reverse on deny,
> reconcile down to realized spend). See ADR-0016 for the normative contract.

- Status: Accepted
- Decision owner: kernel and capability lanes

## Context

Chio capability tokens needed a way to express monetary spending limits for
tool invocations. Requirements were:

1. Avoid floating-point precision issues in financial arithmetic.
2. Support per-invocation cost caps and aggregate total caps.
3. Work safely in HA deployments where multiple Kernel nodes may process
   invocations concurrently with eventual-consistency replication.
4. Integrate with the existing `ToolGrant` structure without breaking the
   attenuation model.
5. Support denial receipt production when budgets are exhausted.

Several alternatives were considered:

- **Floating-point amounts** (f64): ruled out due to precision loss in
  summation over many invocations.
- **Decimal string amounts**: considered but adds parsing overhead and
  complicates canonical JSON.
- **Single-currency u64 minor units**: selected. Simple, deterministic,
  overflow-detectable.

## Decision

Monetary budgets use **u64 minor-unit integers** with a separate ISO 4217
currency code string. For USD, 1 dollar = 100 units (cents). For JPY, 1 yen =
1 unit.

The `MonetaryAmount` type carries both fields:

```rust
pub struct MonetaryAmount {
    pub units:    u64,
    pub currency: String, // ISO 4217, e.g. "USD"
}
```

`ToolGrant` carries two optional monetary budget fields:

- `max_cost_per_invocation: Option<MonetaryAmount>` -- hard cap per single call.
- `max_total_cost: Option<MonetaryAmount>` -- aggregate cap across all calls.

Both fields are optional; a grant with neither set has no monetary limit.

The budget is enforced through the `BudgetStore::try_charge_cost` operation,
which is an atomic SQLite `IMMEDIATE` transaction. The three checks inside the
transaction are:

1. `invocation_count < max_invocations` (if set).
2. `cost_units <= max_cost_per_invocation` (if set).
3. `total_cost_charged + cost_units <= max_total_cost` (if set).

If all checks pass the transaction commits and increments both
`invocation_count` and `total_cost_charged`. If any check fails the
transaction rolls back and the operation returns `false`. No partial updates
are possible.

Arithmetic overflow in step 3 is detected with `checked_add`. If the
addition would overflow `u64`, the Kernel denies the invocation fail-closed
rather than producing an incorrect comparison.

## HA Overrun Bound

In a split-brain scenario, each HA node independently reads from its own
SQLite replica before the LWW merge propagates. As a result, at most one
invocation at `max_cost_per_invocation` can be independently approved by each
active node before the merge catches up.

The maximum possible overrun is bounded by:

```
overrun <= max_cost_per_invocation * node_count
```

This bound is documented in `BudgetStore::try_charge_cost` and is tested by
the `concurrent_charge_overrun_bound` test in `budget_store.rs`. Operators
setting tight total budgets must account for this bound when choosing
`max_cost_per_invocation`.

## No-Refund Model

`total_cost_charged` is monotonically non-decreasing. There is no refund or
credit operation. If a tool call succeeds but the downstream settlement fails,
the Kernel does not automatically reverse the charge. Settlement status is
tracked as an advisory field in `FinancialReceiptMetadata::settlement_status`
for external systems, but the Chio kernel enforces budgets based on committed
charges only.

## Consequences

### Positive

- Deterministic arithmetic with no floating-point error.
- Atomic enforcement: no partial states are observable.
- Denial receipts carry `attempted_cost` so auditors can reconstruct why a
  call was refused.
- `budget_remaining` in receipt metadata gives a best-effort snapshot for
  dashboards.

### Negative

- The overrun bound means operators cannot guarantee hard-stop budgets in HA
  deployments; they can only guarantee soft bounds within the node-count
  multiplier.
- There is no cross-currency conversion; a grant with `currency = "USD"` and
  a cost reported in `"EUR"` will fail the per-invocation check (the kernel
  compares raw units without currency conversion).

## Required Follow-up

- Document the overrun bound prominently in operator guides.
- Consider a future ADR for cross-currency grant validation if multi-currency
  deployments become common.
