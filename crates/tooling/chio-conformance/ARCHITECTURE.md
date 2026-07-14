# chio-conformance architecture

## Overview

`chio-conformance` is a test-support crate: it holds no runtime state and
enforces nothing at the protocol boundary. Its job is to prove that other
Chio crates (the kernel, the MCP edge, the SIEM exporters, the federation
transport, ...) hold their fail-closed and wire-compatibility contracts. It
has three layers: a small library that loads scenarios and orchestrates live
runs (`src/`), a cross-SDK verdict-tuple corpus and diff oracle compiled
directly into its test binaries (`verdict_matrix/`), and a large
negative-conformance and threat-model test suite that links production
crates as dev-dependencies and drives them directly (`tests/`).

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Re-exports the loader, model, native-suite, peers, and runner surfaces. |
| `src/model.rs` | Scenario/result data model: `ScenarioDescriptor`, `ScenarioResult`, `CompatibilityReport`, and their enums. |
| `src/load.rs` | Fail-closed JSON scenario/result loading: rejects missing, non-directory, symlinked, or empty fixture roots. |
| `src/runner.rs` | Live cross-language runner: locates/builds `chio`, spawns `chio mcp serve-http`, drives peer client processes over remote HTTP, collects results. |
| `src/native_suite.rs` | Native (non-MCP) conformance: builds signed capability/delegation/receipt/DPoP/governed-transaction fixtures and drives them via `artifact` (in-process), `stdio`, or `http` executors. |
| `src/peers.rs` | `peers.lock.toml` parsing and validation (schema, https urls, sha256 pins, safe binary paths) and default lockfile path resolution. |
| `src/report.rs` | Markdown compatibility-matrix rendering. |
| `src/bin/*.rs` | Thin CLI wrappers over the library (cross-language runner, report generator, native runner, native fixture server). |

## Conformance run lifecycle

1. `run_conformance_harness` clears and recreates the results directory,
   reserves a loopback port, and locates or builds the `chio` binary.
2. It spawns `chio mcp serve-http` against a policy fixture and a mock
   upstream MCP server, held by a `ChildGuard` that kills the process on
   drop, and polls the port until the server accepts connections.
3. For each requested `PeerTarget`, it spawns the peer's client process (or a
   caller-supplied override binary from `peer_binaries`) against the live
   server and writes its JSON results.
4. It loads every collected result and the scenario descriptors and renders
   `generate_markdown_report`. A failure in any peer process aborts the run
   before a report is written.

The native suite (`run_native_conformance_suite`) does not spawn a Chio
server. Each scenario names an `artifact`, `stdio`, or `http` driver;
`execute_native_scenario` builds the matching fixture in-process, signed with
fixed test keypairs for determinism, and drives it directly against kernel
types, a subprocess speaking the kernel's stdio frame protocol, or a
`chio-native-conformance-fixture` HTTP endpoint.

## Verdict matrix

`verdict_matrix/` is a separate crate (`chio-conformance-verdict-matrix`)
deliberately excluded from the root workspace (it declares its own
`[workspace]` table) so it can be checked standalone. `chio-conformance`'s
five `[[test]]` targets compile its sources directly via
`#[path = "../src/lib.rs"]` rather than depending on it as a library. It
holds:

- A 48-scenario JSON corpus (`scenarios/`) across four categories
  (`capability_subset`, `revocation_propagation`, `replay_verdict`,
  `redaction_determinism`), indexed and hash-pinned by `manifest.toml`.
- `RustKernelDriver`, which runs each scenario through a real in-process
  `chio_kernel::ChioKernel`. It is the only required driver.
- A diff oracle (`diff_oracle.rs`, `cross_language.rs`) that asserts
  `(verdict, reason_code, scope_set)` tuple equality between `rust-kernel`
  and every other driver that reports a scenario as supported.
- External drivers under `drivers/` (Python, Go, TypeScript, JVM, .NET,
  WASM-browser, Kubernetes, Lambda) that replay the same corpus through their
  own SDK or deployment shape, most gated on an operator-supplied
  `CHIO_VERDICT_MATRIX_SIDECAR_URL` and reporting `unsupported` without one.
  Only `drivers/lambda` (`chio-verdict-matrix-driver-lambda`) is a root
  workspace member; the rest build in their native toolchains outside
  `cargo`.

## Invariants and failure modes

- Fixture and scenario loading fails closed: a missing directory, a
  non-directory path, a symlinked escape, or an empty scenario set is an
  error before any scenario runs (`load.rs`, `native_suite.rs`).
- `peers.lock.toml` entries must carry an https url, a 64-character
  lowercase hex sha256, a language in `SUPPORTED_LANGUAGES`, and a binary
  path with no `..` or absolute components. The shipped lockfile's
  placeholder pins are asserted `published = false` in tests so
  `fetch-peers` cannot download an unverified artifact.
- The bundled MCP-core policy fixture must pair
  `allow_ephemeral_receipt_log` with `allow_ephemeral_revocation_store`,
  checked by a runner unit test, or the kernel's revocation durability gate
  denies every mediated call before the harness produces evidence.
- `run_conformance_harness` aborts on the first peer process failure; it does
  not write a partial report.
- The `tests/` suite constructs real `HttpEgressContract`, DSSE, anchor-batch
  witness, and threat-model code paths from forged or adversarial inputs and
  asserts they are rejected, so a failure there is a regression in the crate
  under test, not in this harness.

## Dependencies

`chio-core` is aliased to `chio-core-types`
(`chio-core = { package = "chio-core-types", ... }`); `native_suite.rs` and
`peers.rs` reach it as `chio_core::{canonical, capability, crypto, message,
receipt, sha256_hex}`. `chio-kernel` (not aliased) supplies
`dpop::verify_dpop_proof`/`DpopConfig`/`DpopNonceStore` and the
`transport::{read_frame, write_frame}` frame codec the native suite's
`stdio` driver speaks. `reqwest::blocking` drives the native suite's `http`
executor, `toml` parses `peers.lock.toml`, and `tiny_http` backs the native
fixture binary's HTTP mode. The dev-dependency list is unusually large
because `tests/` links directly against the production crates it
conformance-tests (`chio-siem`, `chio-link`, `chio-openapi-mcp-bridge`,
`chio-a2a-adapter`, `chio-anchor`, `chio-federation-transport-iroh`,
`chio-tee-frame`, `chio-adversarial-suite`, `chio-custody-hw`, ...) instead
of mocking them, so evidence comes from real code paths.

## Extension points

- `ConformanceRunOptions` / `NativeConformanceRunOptions` are the caller
  surface: external consumers point every path (scenarios, results, report,
  policy) at their own layout, and `peer_binaries` lets a caller override any
  `PeerTarget` with a custom binary without editing this crate.
- `peers::PeersLock` is the pinned peer-release contract `chio conformance
  fetch-peers` validates before downloading; adding a peer language means
  extending `SUPPORTED_LANGUAGES` and the runner's peer-dispatch match arms
  together.
