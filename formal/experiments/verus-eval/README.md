# FV-B5 Verus evaluation

This directory is the self-contained workspace for the FV-B5 evaluation
spike specified in
`docs/formal/plan/FV-B5-verus-concurrency-evaluation.md` and executed per
`docs/superpowers/plans/2026-07-23-fv-b5-verus-evaluation.md`. It is an
experiment: nothing here is a lane, appears in any manifest or registry,
or supports any public claim. Where this README and the spec disagree, the
spec wins.

## Charter

Prove the FV-B3 conservation law (partition, terminal uniqueness,
fail-closed arithmetic) for a concurrent multi-hold ledger protocol in a
VerusSync tokenized state machine, unbounded in schedules, actors, and
amounts; falsify the artifact with two broken variants; measure toolchain
cost; feed the spec's decision rule. Concurrency-only: the sequential
module here exists to calibrate effort and estimate absorption cost, not
to add a fourth opinion on the solved sequential surface.

## Pinned toolchain

| Component | Pin |
| --- | --- |
| Verus release | `release/0.2026.07.18.3a4d30b` |
| Source commit | `3a4d30bcdc4571e7927af97be9c4664973083eda` |
| rustc (build requirement) | `1.96.0` |
| z3 | `4.12.5` |
| x86-linux release asset sha256 | `7097a91ea4bf5896a418d90743626cbe5c085ce5ef8a64ed8d84c0aa5e49ac55` |

`tools/install-verus.sh` is the only supported install path. On x86_64
Linux it installs the upstream binary release under the pinned sha256. On
aarch64 Linux, where upstream publishes no binary asset, it builds from
source and refuses to proceed if the cloned commit differs from the pinned
hash. The platform gap is a recorded toolchain-cost finding for the
decision rule, not an inconvenience to silently absorb.

## Verification command

```bash
verus formal/experiments/verus-eval/ledger/src/lib.rs --crate-type=lib
```

The `verus` binary is self-contained (it carries its own rustc linkage,
`vstd`, and z3); `ledger/rust-toolchain.toml` documents the build-time
rustc pin rather than selecting the verification toolchain.

Falsification variants are exercised only through
`tools/run-falsification.sh`, which fails if a mutation verifies.

## Layout

- `tools/install-verus.sh` - pinned fail-closed installer
- `tools/run-falsification.sh` - direction-enforced mutation runner
- `falsification/` - committed failing verifier output
- `ledger/src/sequential.rs` - Phase 1 warm-up (hand transcription of
  `formal_aeneas.rs::ledger_apply`; no drift hash, no claim)
- `ledger/src/sync.rs` - Phase 2 tokenized state machine
- `ledger/src/mutations.rs` - Phase 3 broken variants, cfg-gated
- `MEASUREMENTS.md` - append-only effort log; decision-rule input
