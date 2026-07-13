# Chio Fuzzing

This directory contains Chio's repo-owned `cargo-fuzz` harnesses. It is a
standalone Cargo workspace so libFuzzer / nightly requirements do not leak
into the main stable/MSRV workspace lanes; see `Cargo.toml` for the empty
`[workspace]` stanza that enforces that boundary.

The targets are enumerated in `target-map.toml`, which is the single source of
truth for the harness set: it maps each `[[bin]]` to its owning crate, seed
corpus, and the source-path globs that trigger it on a PR. That file MUST stay
in lockstep with `.clusterfuzzlite/build.sh` and `fuzz/oss-fuzz/build.sh`.
Additional targets add their `[[bin]]` entry in `Cargo.toml` alongside their
`fuzz_target!` definition under `fuzz_targets/` and a `[targets.<name>]` block
in `target-map.toml`. Each target also needs an `owners.toml` entry, at least
three deterministic seeds under `corpus/<name>/`, and one hash-pinned metadata
entry per seed in `corpus_metadata.toml`.

## Setup

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

CI pins a dated nightly so fuzz crashes reproduce across machines; consult
the workflow under `.github/workflows/cflite_pr.yml` and
`.github/workflows/nightly.yml` for the exact toolchain in force.

## Targets

There are 27 targets. Each one drives a trust-boundary decode or
fail-closed-verification surface with arbitrary bytes. The full mapping
(owning crate, source path, trigger globs, seed corpus) lives in
`target-map.toml`; the summaries below are grouped by surface.

### Serialization and canonical form

- `canonical_json` - canonical-JSON round-trip; catches sort drift and float
  canonicalization regressions.
- `capability_receipt` - capability and receipt round-trip across the
  capability-algebra invariants.
- `manifest_roundtrip` - tool-manifest decode plus canonicalization.

### Protocol edges

- `mcp_envelope_decode` - MCP NDJSON decode plus edge dispatch into the
  evaluator.
- `a2a_envelope_decode` - A2A SSE parse plus per-event fan-out.
- `acp_envelope_decode` - ACP NDJSON plus `handle_jsonrpc` dispatch.
- `openapi_ingest` - `OpenApiMcpBridge::from_spec` ingest path.

### Trust, identity, and credentials

- `attest_verify` - Sigstore bundle parser and cert-chain verify.
- `jwt_vc_verify` - JWT VC verifier, including constant-time compare
  assertions.
- `oid4vp_presentation` - OID4VP holder-response decode.
- `did_resolve` - `chio-did` parser plus resolver.
- `federation_trust_establishment` - kernel trust-establishment envelopes,
  peer pins, freshness, and fail-closed resolution.
- `anchor_bundle_verify` - anchor proof bundles plus checkpoint records.

### Kernel, ledger, and policy

- `receipt_log_replay` - receipt-log replay decode plus chain-invariant
  state machine.
- `merkle_checkpoint` (binary `fuzz_merkle_checkpoint`) - Merkle inclusion
  proofs and signed checkpoint validation.
- `revocation_oracle_merkle` - revocation-oracle sparse-Merkle insert,
  inclusion, and non-inclusion proofs.
- `policy_parse_compile` (binary `fuzz_policy_parse_compile`) - HushSpec
  parser, validator, compiler, and YAML round-trip.
- `policy_analyze` - bounded policy relations and evaluator-confirmed
  refinement witnesses.
- `chio_yaml_parse` - `chio-config` YAML loader.
- `eval_receipt_bundle` - eval-report bundle parser and fail-closed verifier.
- `underwriting_policy_input` - underwriting policy, decision, marketplace,
  and premium decode surfaces.

### Guards (WASM, data, tool action)

- `wasm_preinstantiate_validate` - component and Wasmtime backends plus
  format detection.
- `wit_host_call_boundary` - `GuardRequest` / `GuestDenyResponse` serde
  deserialization.
- `wasm_guard_escape` - runtime-execution surface across the escape classes.
- `wasm_guard_smith` - structure-aware modules and components through bounded
  load and evaluation paths.
- `sql_parser` (binary `fuzz_sql_parser`) - SQL parser and fail-closed SQL
  guard analysis across dialects.
- `tool_action` (binary `fuzz_tool_action`) - tool-action classification and
  guard verdicts for egress, shell, SQL, memory, and MCP.

A handful of targets keep a `fuzz_`-prefixed `[[bin]]` name (noted above) so
their seed-corpus directories under `corpus/fuzz_*` line up with cargo-fuzz
defaults.

### Running a target

`attest_verify` is representative: it drives
`chio_attest_verify::SigstoreVerifier::verify_bundle` with arbitrary bytes
split into `(artifact, bundle_json)`. The verifier is fail-closed by
construction, so the target catches parse-path regressions
(unwrap/expect/UB) in the bundle decoder pulled in by `sigstore-rs`. The
seed corpus at `corpus/attest_verify/empty.bin` is a 0-byte file that
mutates outward into both arguments.

Run locally:

```bash
cargo +nightly fuzz run attest_verify
```

Build only (the CI build gate):

```bash
cargo +nightly fuzz build attest_verify
```

Replay every in-process corpus entry and validate the binary, workflow, owner,
and seed-floor inventories with the checked-in lockfile:

```bash
cargo test --locked
```
