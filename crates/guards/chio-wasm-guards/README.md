# chio-wasm-guards

`chio-wasm-guards` is the WASM guard runtime for Chio. It loads `.wasm`
guard modules, compiled from any language that targets WebAssembly, and
executes them under Wasmtime with fuel metering so third-party or
operator-authored guard logic can run inside the kernel's guard pipeline as
an untrusted guest. Two binary shapes are supported and auto-detected at
load time: raw core modules and Component Model components built against
the `chio:guard@0.2.0` WIT world.

Use this crate to run sandboxed WASM guards declared in `chio.yaml` or in
policy with per-guard capability grants. Guard authors should start with
`chio-guard-sdk`; signed module distribution is handled by
`chio-guard-registry`.

## Responsibilities

- Load `.wasm` guard modules (core modules and Component Model components),
  auto-detecting the binary format and executing them under Wasmtime with
  fuel metering, memory limits, and an import-namespace allowlist.
- Verify guard integrity before any guest code runs: manifest SHA-256 hash,
  ABI/WIT world version, and an optional Ed25519 signature sidecar
  (`.wasm.sig`).
- Adapt a loaded guard to the kernel's `Guard` trait (`WasmGuard`),
  translating `GuardContext` into a `GuardRequest` and failing closed on any
  backend error.
- Hot-reload guards in place: publish a replacement module atomically,
  optionally gate it on a frozen canary corpus, and roll back automatically
  when a new epoch's error rate trips a watchdog.
- Enforce a persistent digest blocklist across every reload path, and emit
  Prometheus metric families and `chio.guard`-scoped tracing spans for
  evaluation, reload, and verification.
- Load guards from `chio.yaml` (`wiring::load_wasm_guards`) or from policy
  with capability intersection and `${VAR}` placeholder resolution
  (`runtime::wasmtime_backend::load_guards_from_policy`).

## Public API

- `abi::{WasmGuardAbi, GuardRequest, GuardVerdict}` - the runtime-backend
  trait and the request/verdict types that cross the WASM boundary.
- `runtime::guard::WasmGuard`, `runtime::module::LoadedModule` - the
  kernel-facing `Guard` adapter and its hot-swappable loaded-module epoch.
- `runtime::wasmtime_backend::{WasmtimeBackend, create_backend,
  detect_wasm_format}`, `component::ComponentBackend` (feature
  `wasmtime-runtime`) - the Wasmtime-backed core-module and Component Model
  backends, and the format-detecting factory.
- `manifest::{GuardManifest, SignedWasmModule, verify_guard_signature,
  load_manifest}` - manifest parsing and Ed25519 signature enforcement.
- `hot_reload::{Engine, CanaryCorpus, ReloadWatchdog, WatchdogConfig,
  ReloadTrigger}` - the reload engine, canary verification, and post-swap
  rollback watchdog.
- `blocklist::GuardDigestBlocklist` - the persistent digest deny-list
  consulted before every reload.
- `wiring::{load_wasm_guards, build_guard_pipeline}` (feature
  `wasmtime-runtime`) - `chio.yaml` loading and HushSpec-then-WASM tier
  ordering.
- `runtime::wasmtime_backend::{load_guards_from_policy, PolicyCustomGuard,
  PolicyCustomGuards}` (feature `wasmtime-runtime`) - policy-declared custom
  guard loading with capability intersection.
- `metrics::*`, `observability::*` - Prometheus metric family descriptors
  and `chio.guard`-targeted tracing span builders.

## Feature flags

| Flag | Effect |
|------|--------|
| `wasmtime-runtime` (default) | Enables the Wasmtime backend: `WasmtimeBackend`, `ComponentBackend`, host function wiring, and `chio.yaml`/policy loading. It is the only working execution backend today; a backend-free build (`default-features = false`) keeps the ABI, config, manifest, hot-reload, and metrics types available without pulling in Wasmtime. |
| `tracing-opentelemetry` | Marker feature: declares that this crate's tracing spans are stable for exporters wired with `tracing-opentelemetry` by the embedding binary. Gates no code. |
| `test-support` | Exposes `runtime::mock_backend::MockWasmBackend`, a fixed-verdict backend, for out-of-crate integration tests. |
| `fuzz` | Exposes the `fuzz` module (libFuzzer entry points). Off by default; pulls in `arbitrary`. Enabled only by the standalone `chio-fuzz` workspace. |

## Testing

Requires the `wasm32-unknown-unknown` rustup target:
`rustup target add wasm32-unknown-unknown`. Several integration tests
(`example_guard_integration`, `conformance_runner`) compile Rust example
guards to WASM the first time they run.

```bash
cargo test -p chio-wasm-guards
```

The Python and Go guard round-trip tests (`py_guard_integration`,
`go_guard_integration`) additionally need a prebuilt
`sdks/guard/chio-guard-py/dist/tool-gate.wasm` /
`sdks/guard/chio-guard-go/dist/tool-gate.wasm`; both skip gracefully when
the artifact is absent.

## See also

- `chio-guard-sdk` - guest-side SDK for authoring the guards this crate
  loads and executes.
- `chio-guard-registry` - OCI registry client with Sigstore verification for
  signed guard distribution.
- `chio-policy` - compiles HushSpec policy into the Tier-1 guards that
  `build_guard_pipeline` runs ahead of WASM guards.
- `chio-kernel` - defines the `Guard`, `GuardContext`, and `KernelError`
  contract this crate implements against.
