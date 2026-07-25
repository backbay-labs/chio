# Kernel Embedder Surface Migration

Two kernel surfaces changed in ways that affect embedders who build a
`ChioKernel` directly or implement `ToolEvaluator` themselves. Both changes are
fail-closed: an embedder that does nothing gets a denial or a configuration
error rather than a silent behaviour change.

## Settlement observer installation is fallible

`set_settlement_observer` is replaced by `set_settlement_observer_runtime`,
which takes the settlement hook together with its durable outcome store and
retry policy, and returns `Result<(), KernelError>`.

```rust
kernel.set_settlement_observer_runtime(hook, outcome_store, retry_policy)?;
```

### The return value must not be discarded

A swallowed error leaves the kernel dispatching charges with settlement
uninstalled, which is the charge-without-settle window the atomic projection
exists to close. Propagate it, or fail startup on it.

### Required receipt-store capabilities

The receipt store paired with a settlement runtime must implement three
`ReceiptStore` methods:

| Method | Required value |
|--------|----------------|
| `settlement_store_binding` | `Some(binding)` matching the outcome store's binding |
| `atomic_receipt_projection` | `AtomicReceiptProjection::SettlementObservationV1` |
| `supports_atomic_receipt_projection_with_timeout` | `true` |

The defaults are `None` and `Unsupported`, so a store that does not opt in
cannot install settlement. This is a trait contract rather than a SQLite
requirement: any store can opt in by implementing those three methods.

The timeout capability is required so a legacy atomic-only store cannot
reintroduce an unbounded writer wait. There is deliberately no degraded
non-atomic mode.

### Configuration order

The store and the runtime may be configured in either order. Both setters
validate symmetrically, and attaching an incompatible store fails without
replacing the store already installed.

### Failure modes

| Error | Cause |
|-------|-------|
| `UnsupportedAtomicProjection` | store lacks `SettlementObservationV1` or the timeout capability |
| `MissingStoreBinding` | store returns `None` from `settlement_store_binding` |
| `StoreBindingMismatch` | receipt store and outcome store name different backends |

## `ToolEvaluator::dispatch` no longer has a working default

The default body of `ToolEvaluator::dispatch` now denies every direct dispatch
with `KernelError::DirectDispatchUnavailable`, reported as
`CHIO-KERNEL-DIRECT-DISPATCH-UNAVAILABLE`. This is broader than the previous
behaviour, which only refused monetary dispatch.

Direct phase dispatch cannot retain the admission operation, compensation,
outcome, and receipt as one durable lifecycle, so the surface was withdrawn
rather than left partially correct.

Because `dispatch` is a trait default, implementors that override it are
unaffected. Implementors that relied on the default must call
`ToolEvaluator::evaluate`, which runs the full pipeline:

```rust
let response = evaluator.evaluate(&kernel, &request).await?;
```
