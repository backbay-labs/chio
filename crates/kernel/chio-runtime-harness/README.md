# chio-runtime-harness

Runs a Chio runtime loopback scenario end to end: admission evaluation, live
`chio-kernel` execution, and proof-package assembly, then checks the regenerated
proof for parity against a static baseline package and verifier report. It exists
so a checked-in proof fixture can be validated against what the current kernel and
runtime-admission code actually produce, and fails closed the moment it doesn't.

The crate does real file I/O: a JSON-backed admission store and temporary SQLite
receipt/revocation stores under `store_dir`, and evidence JSON under `out_dir`. It
is driven by `chio-cli`'s runtime-loopback and proof-fixture commands, not by a
production kernel.

## Responsibilities

- Normalize a scenario file into an ordered list of steps and evaluate each one
  through `chio_runtime_core::evaluate_runtime_admission`, stopping at the first
  rejection.
- Dispatch each accepted step through a real, disposable `ChioKernel` (temp SQLite
  receipt and revocation stores, a stub tool server) to obtain a live, kernel-signed
  `ChioReceipt`.
- Build treaty scope, ladder intersection, continuation, receipt lineage, and
  bilateral DSSE artifacts for federated steps, and feed them to the kernel's own
  runtime admission hook.
- Rebuild the buyer-side federation closure for the first destructive, governed
  step that produced a treaty context, re-evaluating
  `evaluate_cross_boundary_admission`.
- Assemble the live receipts into a proof package, verify it, and diff it
  field-by-field against a static baseline.
- Write every intermediate artifact as SHA-256-addressed evidence JSON with a
  manifest, under a validated relative path.

## Public API

- `run_runtime_loopback_scenario(scenario, store_dir, now_unix_ms, out_dir)` - runs
  a scenario against the crate's built-in fixture baseline
  (`chio_attest_loopback::fixture_proof_package` / `fixture_verifier_report`).
- `run_runtime_loopback_scenario_with_static_artifacts(scenario, store_dir,
  now_unix_ms, out_dir, static_package_json, static_report_json)` - same, with a
  caller-supplied static baseline.
- `runtime_loopback_capability_window(now_unix_ms) -> (u64, u64)` - derives a
  second-denominated capability `(not_before, not_after)` window from a
  millisecond scenario clock.
- `RuntimeLoopbackError` - the crate's single error type.

All other modules (`admission_loop`, `buyer_closure`, `evidence_io`, `kernel`,
`proof_assembly`, `proof_parity`, `scenario`, `treaty`) are crate-private.

## Usage

```rust
use std::path::Path;

fn regenerate(scenario: &Path, store_dir: &Path, out_dir: &Path)
    -> Result<(), chio_runtime_harness::RuntimeLoopbackError>
{
    chio_runtime_harness::run_runtime_loopback_scenario(
        scenario,
        store_dir,
        1_800_000_000_000,
        out_dir,
    )
}
```

## Testing

`cargo test -p chio-runtime-harness`

The `src/lib.rs` tests replay
`examples/chio-3vendor/fixtures/runtime-spine/scenario.json` after rewriting it
into an executable scenario, and expect a `runtime_proof_semantic_parity_mismatch`
failure: the crate's built-in fixture baseline does not match a freshly executed
run of that scenario.

## See also

- `chio-runtime-core` - the admission evaluator, treaty/ladder types, and evidence
  schemas this crate drives.
- `chio-kernel` - the live kernel each accepted step is dispatched through.
- `chio-attest-buyer-core`, `chio-attest-loopback` - proof package assembly,
  verification, and fixture signing keys.
- `chio-cli` - the `runtime run-loopback` and proof-fixture commands that call this
  crate.
