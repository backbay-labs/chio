# chio-replay-gate

Deterministic-replay corpus driver and golden infrastructure for the Chio
kernel.

This crate is the deterministic-replay gate. It is a sibling of
`tests/conformance/` (cross-implementation conformance) and `tests/e2e/`
(end-to-end integration tests). Where those crates exercise current kernel
behaviour against semantic specs, `chio-replay-gate` pins **byte-exact**
kernel output across versions: a curated corpus of 50 input scenarios is
replayed on every PR and the produced receipts, anchor checkpoint, and Merkle
root are byte-compared against checked-in goldens.

The normative specification for this gate lives in `spec/PROTOCOL.md`.
Read it before changing anything that affects fixture layout, golden format,
or `--bless` semantics.

## How it works

Every fixture flows through the same deterministic execution context so that
replay output is byte-identical across machines and operating systems:

- A fixed Ed25519 signing key is loaded from `tests/replay/test-key.seed`.
- The clock is pinned at `2026-01-01T00:00:00Z`.
- Nonces are strictly monotonic 16-byte values from an in-memory counter.
- Directory enumeration is forced into `LC_ALL=C` byte order.

Goldens are read back as raw `Vec<u8>` and byte-compared against a candidate
run, so any drift in whitespace, key order, or line endings is caught without
a `serde_json` round-trip masking it.

## Layout

```
tests/replay/
  Cargo.toml                  # crate manifest
  README.md                   # this file
  release_compat_matrix.toml  # cross-version receipt-compatibility matrix
  corpus_pins.toml            # pinned corpus metadata
  src/
    lib.rs                    # crate root and module map
    main.rs                   # binary entry, replay-gate runner
    driver.rs                 # Scenario + ScenarioDriver (fixed clock, nonce, signer)
    golden_writer.rs          # NDJSON receipts, JSON checkpoint, hex root writer
    golden_reader.rs          # reads goldens back as raw Vec<u8>
    golden_format.rs          # shared on-disk format contract
    byte_compare.rs           # byte-equivalence harness
    fs_iter.rs                # deterministic LC_ALL=C directory enumeration
    bless.rs                  # --bless gate logic
    cross_version/            # cross-version compat matrix loader, fetch, reverify
  test-key.seed               # 32-byte deterministic Ed25519 seed; non-production
  keys/                       # public verifying key for the seed above
  fixtures/                   # 50 input scenarios across 10 families
    allow_metered/...
    allow_simple/...
    allow_with_delegation/...
    deny_expired/...
    deny_revoked/...
    deny_scope_mismatch/...
    guard_rewrite/...
    replay_attack/...
    tampered_canonical_json/...
    tampered_signature/...
  goldens/                    # blessed outputs; updated only via --bless
    allow_metered/...
    ...
```

## Build and run

```
cargo build -p chio-replay-gate --tests
cargo test -p chio-replay-gate
```

The `corpus_smoke` test enumerates the corpus and asserts every manifest is
well-formed; `golden_byte_equivalence` replays each fixture and byte-compares
the output against its golden. The CI gate runs under
`.github/workflows/chio-replay-gate.yml`.

## Adding a fixture

A fixture is a JSON manifest plus an `inputs/` directory under one of the ten
family subdirectories of `tests/replay/fixtures/`. After authoring the
manifest, produce its golden by running the gate with `--bless`.

## Bless flow

`--bless` is the only supported way to update goldens. It is gated by the
rules documented in `spec/PROTOCOL.md` (allowed branch, environment, and an
audit-log entry under `docs/replay-compat.md`). Direct edits to
`tests/replay/goldens/**` are out of policy.
