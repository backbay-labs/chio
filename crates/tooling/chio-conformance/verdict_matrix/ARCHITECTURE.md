# chio-conformance-verdict-matrix architecture

## Overview

`chio-conformance-verdict-matrix` is the semantic-equality test harness for
Chio tool-access verdicts. It owns a hash-pinned scenario corpus and a diff
oracle; every consumer is a test binary that evaluates the corpus through one
driver, reduces the result to a `(verdict, reason_code, scope_set)` tuple, and
diffs it against the scenario's expected tuple and against every other
driver's tuple for the same scenario. The reference driver runs a real
in-process `ChioKernel`, so the kernel is ground truth and every other driver
(external SDK, deployment-shape sidecar relay, WASM browser kernel) is a claim
checked against it. The crate has no production runtime role and is not a
dependency of any shipped binary.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `Verdict`, `ScenarioCategory`, `VerdictTuple` (`normalized()` sorts `scope_set`, does not dedupe), schema/path constants, and the `driver`/`diff_oracle`/`cross_language` module declarations. Inline `#[cfg(test)]` unit tests. |
| `src/driver.rs` | `VerdictScenario`/`ScenarioScript` deserialization and identity-field validation; `RustKernelDriver`, the in-process reference driver that builds a `ChioKernel`, registers a synthetic `MatrixToolServer`, issues/revokes capabilities, and evaluates each scenario. Inline unit tests. |
| `src/diff_oracle.rs` | `VerdictMatrixManifest` parsing/validation, SHA-256 corpus indexing (`scenario_index_hash`, `verify_manifest_corpus_hash`), reason-code registry loading, and expected-vs-driver tuple diffing. No inline tests; exercised only by `tests/diff_oracle_self_test.rs`. |
| `src/cross_language.rs` | `CrossLanguageReport` aggregation and `diff_cross_language`/`diff_cross_language_against_expected`, the pairwise driver-vs-driver and driver-vs-expected comparison. Inline unit tests. |
| `manifest.toml` | Pins the corpus root, scenario count and category breakdown, SHA-256 corpus hash, and the per-driver registry (status, entrypoint, sidecar/env requirements) `diff_oracle` and `deployment_shape_smoke` validate against. |
| `SCENARIOS.md` | Normative scenario JSON schema: required/optional fields, the verdict tuple shape, and the compatibility rules (unknown top-level fields rejected, unknown `script` fields preserved). |
| `scenarios/**.json` | The 48-scenario corpus in 4 category directories (`capability_subset`, `revocation_propagation`, `replay_verdict`, `redaction_determinism`), 12 scenarios each. |
| `drivers/rust/` | Documentation only; the reference driver is `src/driver.rs`. |
| `drivers/{python,go,typescript}/` | Standalone SDK driver scripts loaded directly by each SDK's own test suite, e.g. the Python SDK's `test_verdict_matrix.py` loads `drivers/python/run_scenarios.py` by file path. |
| `drivers/wasm-browser/` | `run.sh` entrypoint for the WASM browser kernel path; capability category only. |
| `drivers/{jvm,dotnet,k8s,lambda}/` | Deployment-shape drivers that relay scenarios to an operator-supplied sidecar over `POST /chio/evaluate`. `drivers/lambda` is a Rust crate and the only one of the four that is a root-workspace member. |
| `tests/*.rs` | The five files `chio-conformance/Cargo.toml` registers as `[[test]]` targets; each re-includes `src/lib.rs` via `#[path]`, and Cargo's default test auto-discovery also picks them up as this crate's own integration tests. |

## Compilation shapes

- Not a root-workspace member. `Cargo.toml` declares `[workspace]`, rooting
  its own workspace (own `Cargo.lock`), so `cargo check --manifest-path
  verdict_matrix/Cargo.toml` resolves independently, e.g. for a standalone
  SDK deployment audit.
- `chio-conformance/Cargo.toml` never depends on this crate. It registers
  five `[[test]]` targets pointing at `verdict_matrix/tests/*.rs`; each of
  those files opens the module tree with `#[path = "../src/lib.rs"] mod
  verdict_matrix;` instead of a crate dependency edge, so the source compiles
  as a module inside `chio-conformance`'s own test binaries and resolves
  `chio_core`, `chio_kernel`, `chio_kernel_browser`, `serde_yaml`, and
  `async-trait` from `chio-conformance`'s `[dependencies]`/`[dev-dependencies]`
  rather than this crate's.
- Because the same `tests/*.rs` files also live under this crate's own
  `tests/` directory and `autotests` is not disabled, they are additionally
  auto-discovered as this crate's own integration tests when built
  standalone, resolving against this crate's own `Cargo.toml` instead. The
  `#[path]` include, not a crate dependency, is what keeps both compilation
  contexts building from identical source.
- A crate cannot belong to two workspaces at once. `drivers/lambda` carries
  no `[workspace]` of its own, so it, and only it, is listed in the root
  workspace's `members`.

## Scenario evaluation flow

1. `manifest.toml` pins the corpus root, scenario count, category breakdown,
   and a SHA-256 corpus hash; `diff_oracle::verify_manifest_corpus_hash`
   recomputes the hash from `scenarios/**.json` and fails if the manifest is
   stale relative to the corpus on disk.
2. `driver::load_scenarios` walks `scenarios/`, deserializes each JSON file
   into a `VerdictScenario`, and rejects malformed identity fields
   (`VerdictScenario::validate`) before any driver sees the scenario.
3. Each driver reduces a scenario to a `VerdictTuple`. The reference driver
   (`RustKernelDriver::run`) builds a fresh `ChioKernel`, issues (and
   optionally revokes) a capability, registers `MatrixToolServer`, and
   evaluates a `ToolCallRequest`; replay scenarios additionally drive the
   execution-nonce store through fresh/duplicate/stale/trace-missing
   presentation, and redaction scenarios attach a `Guard` or
   `PostInvocationHook`.
4. `diff_oracle::diff_manifest_reports` (single driver against the expected
   map) or `cross_language::diff_cross_language` (multiple drivers) compares
   every driver's tuples against the scenario's `expected` tuple and, for the
   cross-language gate, against every other driver's tuple for the same
   scenario.
5. `cross_language::divergence_summary` renders any divergence as a
   human-readable multi-line string for test failure output.

## Invariants and failure modes

- `VerdictScenario::validate` rejects empty, whitespace-padded, or
  control-character identity fields (id, tags, requires, expected reason
  code, expected scope set, script operation/tool/required_scope) before any
  driver sees the scenario. `VerdictScenario` denies unknown top-level
  fields; `ScenarioScript` preserves unknown fields in `extra` instead of
  rejecting them.
- `verify_manifest_corpus_hash` fails closed if the on-disk scenario count or
  SHA-256 index hash (`sha256(relative-path-tab-file-sha256-newline)` over
  every scenario file) does not match `manifest.toml`; an edited corpus
  without a re-pinned manifest fails the gate instead of silently passing.
- `VerdictTuple::normalized` sorts `scope_set` but does not deduplicate it;
  duplicate-scope preservation is an explicit, tested contract.
- `diff_cross_language` requires every driver named in
  `manifest.drivers.required` (currently `rust-kernel` only) to emit a tuple
  for every expected scenario. Other drivers may report a scenario
  `unsupported`; a missing tuple from a non-required driver is not a
  divergence, but any tuple a driver does emit must match both the expected
  tuple and every other driver's tuple for that scenario.
- `validate_reason_codes` rejects any expected reason code other than
  `REASON_NONE` (`urn:chio:error:none`) that is not present in
  `spec/errors/registry.yaml`.
- The JVM, dotnet, k8s, and Lambda deployment-shape drivers fail closed on an
  unreachable sidecar: an unset `CHIO_VERDICT_MATRIX_SIDECAR_URL` (or
  `CHIO_SIDECAR_URL` fallback) reports every scenario `unsupported`, but a
  configured-and-unreachable sidecar reports `fail`, never a silent skip.

## Dependencies

Standalone workspace (`verdict_matrix/Cargo.toml`): `chio-core` (aliased to
`chio-core-types`) for capability, crypto, and receipt types; `chio-kernel`
for `ChioKernel` and the `ToolServerConnection`/`Guard`/`PostInvocationHook`
traits the reference driver implements against; `chio-kernel-browser`
(declared here but only actually used from `tests/verdict_matrix_cross_language.rs`,
not from `src/`); `serde`/`serde_json`/`serde_yaml`/`toml` for scenario,
manifest, and reason-registry parsing; `thiserror` for error enums;
`async-trait` for the async `ToolServerConnection` impl.

Embedded mode: the same source instead resolves against `chio-conformance`'s
dependency graph, a superset that also supplies the `chio_kernel_browser`
path the cross-language test exercises.

## Extension points

Adding a driver: register it under `[drivers.<id>]` in `manifest.toml`
(status, entrypoint, and either a `command` or `requires_sidecar_env`),
implement it under `drivers/<id>/` (or, for a wire-compatible sidecar relay,
model it on `drivers/lambda`), and produce a `VerdictTuple` per scenario
using the same reason-code vocabulary as `driver`'s `REASON_*` constants.
There is no shared Rust driver trait; conformance is structural (same tuple
shape, same reason-code vocabulary) rather than an interface implementation.
A driver that cannot evaluate a scenario must report it `unsupported`, never
a guessed pass or fail.
