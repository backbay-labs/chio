# chio-replay-gate

Deterministic-replay corpus driver and golden infrastructure for the Chio
kernel.

This crate implements the M04 deterministic-replay gate. It is a sibling of
`tests/conformance/` (cross-implementation conformance) and `tests/e2e/`
(end-to-end integration tests). Where those crates exercise current kernel
behaviour against semantic specs, `chio-replay-gate` pins **byte-exact**
kernel output across versions: a curated corpus of 50 input scenarios is
replayed on every PR and the produced receipts, anchor checkpoint, and Merkle
root are byte-compared against checked-in goldens.

The source-of-truth specification for this gate lives in
`.planning/trajectory/04-deterministic-replay.md`. Read it before changing
anything that affects fixture layout, golden format, or `--bless` semantics.

## Status

This crate ships incrementally across M04 Phase 1:

| Ticket    | Scope                                                       |
| --------- | ----------------------------------------------------------- |
| M04.P1.T1 | Workspace-member skeleton (this commit).                    |
| M04.P1.T2 | `Scenario` plus `ScenarioDriver` (fixed clock, deterministic nonce, signer from `test-key.seed`). |
| M04.P1.T3 | Golden writer (NDJSON receipts, JSON checkpoint, hex root). |
| M04.P1.T4 | Golden reader and byte-comparison harness.                  |
| M04.P1.T5 | 50 fixture manifests across the eight families.             |
| M04.P1.T6 | `cargo test -p chio-replay-gate` glue (`corpus_smoke`).     |
| M04.P1.T7 | `LC_ALL=C` plus explicit directory-listing sort.            |

M04 Phase 2 then adds the CI workflow (`.github/workflows/chio-replay-gate.yml`),
the `--bless` flag with branch / env / audit-log gating, and the initial bless
of all 50 goldens.

T1 (this commit) wires the crate into the workspace so that later tickets have
a stable home. There is no public API yet and the binary is a no-op.

## Layout (planned)

```
tests/replay/
  Cargo.toml          # this crate (T1)
  README.md           # this file (T1)
  src/
    lib.rs            # crate root, module map (T1)
    main.rs           # binary entry, replay-gate runner (T1; logic in T2+)
    driver.rs         # Scenario + ScenarioDriver (T2)
    golden.rs         # writer / reader / byte comparison (T3, T4)
    bless.rs          # --bless gate logic (Phase 2)
  test-key.seed       # 32-byte deterministic Ed25519 seed; non-production (T2)
  fixtures/           # 50 input scenarios across 8 families (T5)
    allow_simple/...
    deny_capability/...
    ...
  goldens/            # blessed outputs; updated only via --bless (Phase 2)
    allow_simple/...
    ...
```

## Build

```
cargo build -p chio-replay-gate --tests
```

## Adding a fixture (placeholder; full flow lands in T5)

Once T2-T5 land, a fixture is a JSON manifest plus an `inputs/` directory under
one of the eight family subdirectories of `tests/replay/fixtures/`. Goldens are
produced by running the gate with `--bless` (Phase 2).

## Bless flow (placeholder; full flow lands in M04.P2)

`--bless` is the only supported way to update goldens. It is gated by the rules
documented in `.planning/trajectory/04-deterministic-replay.md` (allowed branch,
environment, audit-log entry under `docs/replay-compat.md`). Direct edits to
`tests/replay/goldens/**` are out of policy.
