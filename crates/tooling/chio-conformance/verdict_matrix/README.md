# chio-conformance-verdict-matrix

Scenario corpus, reference driver, and diff oracle for the Chio cross-SDK
verdict comparison harness. Defines a hash-pinned corpus of scenarios, each
naming an operation and an expected `(verdict, reason_code, scope_set)`
tuple, and compares that expected tuple against what the in-process Rust
kernel and every external SDK or deployment-shape driver actually produces.

This directory is not a member of the root Cargo workspace: its `Cargo.toml`
declares its own `[workspace]` so it can be checked and built standalone. Its
sources are also compiled a second way: `chio-conformance/Cargo.toml`
registers five `[[test]]` targets whose files re-include `src/lib.rs` via
`#[path]`, so the same module tree runs inside `chio-conformance`'s package
and dependency graph instead. See "Compilation shapes" in `ARCHITECTURE.md`.

## Responsibilities

- Own the verdict vocabulary and schema constants every driver and the diff
  oracle share (`Verdict`, `ScenarioCategory`, `VerdictTuple`,
  `MANIFEST_SCHEMA`, `SCENARIO_SCHEMA`).
- Load and validate the JSON scenario corpus under `scenarios/`, rejecting
  scenarios with empty, whitespace-padded, or control-character identity
  fields at load time (`driver::load_scenarios`).
- Run the reference driver: an in-process `ChioKernel` that evaluates every
  scenario for real (capability issuance and revocation, tool invocation,
  guard and post-invocation redaction, execution-nonce replay checks) and
  reduces the response to a `VerdictTuple` (`driver::RustKernelDriver`).
- Load `manifest.toml`, verify its SHA-256 corpus pin against the scenario
  files on disk, and validate expected reason codes against
  `spec/errors/registry.yaml` (`diff_oracle`).
- Diff driver output against the expected tuple and, for the cross-language
  gate, against every other driver's tuple for the same scenario, fail-closed
  on any divergence (`diff_oracle`, `cross_language`).

## Public API

`src/lib.rs`: `Verdict` (`Allow`/`Deny`/`Error`), `ScenarioCategory`
(`Capability`/`Revocation`/`Replay`/`Redaction`/`Receipt`), `VerdictTuple`
(`normalized()` sorts `scope_set` without deduplicating it), and the schema
constants.

`driver`: `VerdictScenario`, `ScenarioScript`, `load_scenario_file`,
`load_scenarios`, `category_counts`; `RustKernelDriver::{run, run_all}`;
`DriverOutcome`, `DriverStatus`; the reason-code constants `REASON_NONE`,
`REASON_SCOPE_EXCEEDED`, `REASON_REVOKED`, `REASON_REPLAY_DRIFT`,
`REASON_REPLAY_TRACE_MISSING`, `REASON_INPUT_REDACTED`,
`REASON_OUTPUT_REDACTED`, `REASON_GUARD_DENIED`, `REASON_KERNEL_INTERNAL`.

`diff_oracle`: `VerdictMatrixManifest`, `load_manifest`,
`verify_manifest_corpus_hash`, `scenario_index_hash`; `DriverReport`,
`TupleDivergence`, `diff_expected_reports`, `diff_manifest_reports`,
`expected_tuple_map`; `load_error_registry_urns`, `validate_reason_codes`.

`cross_language`: `CrossLanguageReport`, `CrossLanguageDivergence`
(`DriverVsExpected`/`DriverVsDriver`), `diff_cross_language`,
`diff_cross_language_against_expected`, `divergence_summary`.

## Driver layout

`manifest.toml` registers every driver by id. The reference driver's code is
this crate's own `src/driver.rs`; everything else under `drivers/` is a
separate, independently-built implementation against the same corpus.

| Driver id(s) | Status | Entrypoint |
|---|---|---|
| `rust-kernel` | required, active, in-process | `src/driver.rs` (`drivers/rust/` holds only its README) |
| `python-sdk` | active | `drivers/python/run_scenarios.py`, loaded by the SDK's own pytest suite |
| `go-http-sdk` | active | `drivers/go/run_scenarios.go`, run by the SDK's own test suite |
| `typescript-node-http` | transport-client, needs an operator sidecar | `drivers/typescript/run_scenarios.ts` |
| `typescript-ai-sdk-middleware`, `typescript-chio-next` | transport-client | `drivers/typescript/*.ts`, wrap `typescript-node-http` |
| `wasm-browser` | partial, capability category only | `drivers/wasm-browser/run.sh` |
| `jvm-sdk`, `dotnet-sdk`, `k8s-admission-webhook` | transport-client, deployment-shape | `drivers/{jvm,dotnet,k8s}`, relay to a sidecar over `POST /chio/evaluate` |
| `lambda-deployment-shape` | transport-client, deployment-shape | `drivers/lambda`, the one driver that is a root-workspace member (`chio-verdict-matrix-driver-lambda`) |

## Testing

Standalone workspace:

```bash
cargo test --manifest-path crates/tooling/chio-conformance/verdict_matrix/Cargo.toml
```

Embedded in `chio-conformance` (what CI runs):

```bash
cargo test -p chio-conformance --test verdict_matrix_rust_driver
cargo test -p chio-conformance --test diff_oracle_self_test
cargo test -p chio-conformance --test verdict_matrix_cross_language
cargo test -p chio-conformance --test verdict_matrix_typescript
cargo test -p chio-conformance --test deployment_shape_smoke
```

Both modes compile the same `tests/*.rs` files; the embedded runs resolve
`chio_core`, `chio_kernel`, `chio_kernel_browser`, and `serde_yaml` from
`chio-conformance`'s dependency graph rather than this crate's own.

## See also

- `chio-conformance` - owns the manifest entry point, registers the five
  `[[test]]` targets, and documents the suite-level conformance flow.
- `chio-kernel` - the request evaluator the reference driver exercises.
- `chio-kernel-browser` - the WASM browser kernel the cross-language test
  compares against the reference driver.
- `docs/conformance/verdict-matrix.md` - the corpus and driver runbook.
