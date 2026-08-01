# chio-chaos

Real fault-injection harness for the Chio receipt store and kernel hot path.
Each scenario induces a genuine fault against a live stack and asserts the
system fails closed with a typed error and then recovers. This replaces the
prior arrangement where the declared fault classes were never executed and only
hand-committed signed reports asserted `status: passed`.

## What it boots

Store scenarios drive a live `chio_store_sqlite::SqliteReceiptStore` directly;
kernel-path scenarios drive the real `chio_kernel::ChioKernel` through
`chio_loadgen::StackHarness`. The SIGKILL and SIGTERM scenarios run a separate
victim process (`chaos_victim`), located through `CARGO_BIN_EXE_chaos_victim`;
the tests never shell out to cargo.

## Scenarios and what they assert

- SIGKILL-mid-append: the victim appends a receipt, flushes as a durability
  barrier, and only then records an `ack <seq>` line. The parent SIGKILLs it
  mid-loop, reopens the store, and `check_durable_acks` proves every
  acknowledged receipt survived: the acked `entry_seq` is at or below the
  recovered committed floor and reads back.
- SIGTERM-drain: same durable-ack invariant under SIGTERM (default termination)
  instead of SIGKILL; the assertion is exit-by-signal within a bounded window
  plus a passing `check_durable_acks`.
- ENOSPC: a bounded `max_page_count` forces `SQLITE_FULL`; the store must deny
  with the typed `ReceiptStoreError::Sqlite` disk-full surface, then recover.
- Wedged-writer: a competing writer holds the write lock; the store must surface
  a typed `SQLITE_BUSY` deny (no silent success) and reseed on recovery.
- Retention-under-load: retention maintenance races appends; the verified head
  stays consistent and no reopen bricks.
- Hung-tool-server: the tool stub sleeps far past the dispatch deadline; the
  kernel must return a typed deadline deny rather than hang.
- Blocking-guard: a guard blocks far past the guard-pipeline deadline; the
  kernel must fire the guard timeout and deny fail-closed.

Every scenario carries the `InjectionNoOp` discipline: if the fault provably
never took effect (for example a dispatch that returns a normal `Allow`, proving
the deadline never fired), the scenario fails with `ChaosError::InjectionNoOp`
rather than passing vacuously. No `unwrap`/`expect`; every path yields a typed
`ChaosError`.

## Env knobs

| Variable | Default | Meaning |
| --- | --- | --- |
| `CHIO_CHAOS_ITERATIONS` | small PR-tier value (3) | crash/round count; the nightly lane raises it |
| `CHIO_CHAOS_SEED` | fixed per-test seed | deterministic RNG seed (decimal or `0x`-hex); printed on entry so a failure reproduces |

## Run locally

```bash
# Default PR-tier run:
cargo test -p chio-chaos --features chaos-victim

# Extra flake shake at higher strength:
CHIO_CHAOS_ITERATIONS=10 cargo test -p chio-chaos --features chaos-victim

# Pin a seed to reproduce a failure:
CHIO_CHAOS_SEED=0xC10A0515 cargo test -p chio-chaos --features chaos-victim
```

The nightly lane `.github/workflows/chio-chaos-nightly.yml` runs the suite at a
raised `CHIO_CHAOS_ITERATIONS`.

## Scope caveats

- This branch injects the faults for real in-tree. It does NOT yet regenerate or
  sign the `chaos-run` / `attack-simulation` fixtures the transaction-passport
  verifier consumes; those signed fixtures remain hand-committed. Closing that
  evidence-pipeline half (runner-key signing, freshness gate) is a follow-up.
- SIGKILL proves process-crash recovery, not power-loss durability. The OS page
  cache survives SIGKILL, so this does not exercise a torn write from lost
  hardware buffers.
- The retention scenario exercises reseed-under-load serialization, not the
  destructive prune/delete path; no orphan state is seeded.
- The `RelayOutage` federation scenario named in the load-soak-chaos plan is not
  implemented here (it needs federation relay infrastructure).
