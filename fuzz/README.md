# Chio Fuzzing

This directory contains Chio's repo-owned `cargo-fuzz` harnesses. It is a
standalone Cargo workspace so libFuzzer / nightly requirements do not leak
into the main stable/MSRV workspace lanes; see `Cargo.toml` for the empty
`[workspace]` stanza that enforces that boundary.

M02 owns the fuzz lane and lands the seven baseline targets enumerated in
`target-map.toml`. Later trajectory tickets layer their target-specific
`[[bin]]` entries alongside their `fuzz_target!` definitions.

## Setup

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

CI pins a dated nightly so fuzz crashes reproduce across machines; consult
the workflow under `.github/workflows/cflite_pr.yml` and
`.github/workflows/nightly.yml` for the exact toolchain in force.

## Targets

### `attest_verify`

Drives `chio_attest_verify::SigstoreVerifier::verify_bundle` with arbitrary
bytes split into `(artifact, bundle_json)`. The verifier is fail-closed by
construction, so the target catches parse-path regressions
(unwrap/expect/UB) in the bundle decoder pulled in by `sigstore-rs`. The
seed corpus at `corpus/attest_verify/empty.bin` is a 0-byte file that
mutates outward into both arguments.

Run locally:

```bash
cargo +nightly fuzz run attest_verify
```

Build only (the M09.P3.T5 gate):

```bash
cargo +nightly fuzz build attest_verify
```
