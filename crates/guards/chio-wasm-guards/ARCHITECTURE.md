# chio-wasm-guards architecture

## Overview

`chio-wasm-guards` is the sandboxed-guard execution runtime in the Chio
kernel's guard pipeline. Every loaded `.wasm` module is an untrusted guest:
the crate enforces fuel metering, memory limits, an import-namespace
allowlist, manifest hash and ABI/WIT-version checks, and optional Ed25519
signatures, all fail-closed, before any guest instruction runs. Two binary
shapes are auto-detected at load time: core modules and Component Model
components built against the `chio:guard@0.2.0` WIT world
(`wit/chio-guard/world.wit`). Most of the crate compiles without the
`wasmtime-runtime` feature (the ABI types, manifest/signing, hot reload, the
blocklist, metrics, and observability are backend-agnostic); only execution
itself (`WasmtimeBackend`, `ComponentBackend`, host bindings,
`chio.yaml`/policy loading) requires it.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Module index and re-export surface. Everything but `fuzz` is `cfg(not(loom))`; a `loom` build compiles only a marker constant. |
| `src/abi.rs` | `GuardRequest`, `GuardVerdict`, the `WasmGuardAbi` backend trait, and the guest deny-reason protocol. |
| `src/config.rs` | `WasmGuardConfig`, the single-guard `chio.yaml` entry: fuel limit, priority, advisory flag, size caps. |
| `src/manifest.rs` | `guard-manifest.yaml` parsing, SHA-256 verification, ABI/WIT gating, and Ed25519 sidecar (`.wasm.sig`) signing and verification. |
| `src/blocklist.rs` | `GuardDigestBlocklist`, persisted at `${XDG_STATE_HOME}/chio/guards/blocklist.json`. |
| `src/hot_reload.rs`, `src/incident.rs` | `Engine<F>`: guard registry, canary verification, debounced reload, file/registry triggers, `ReloadWatchdog` rollback, writing `ReloadIncident` evidence (`IncidentWriter`) under `${XDG_STATE_HOME}/chio/incidents`. |
| `src/metrics.rs` | Prometheus family descriptors and cardinality-bounded `GuardMetricRegistry` / `GuardPoolMetrics`. |
| `src/observability.rs` | Tracing span builders, pinned to the `chio.guard` target. |
| `src/placeholders.rs` | `${VAR}` / `${VAR:-default}` substitution against an injected `PlaceholderEnv`. |
| `src/bundle_store.rs` | `BundleStore` / `InMemoryBundleStore`, backing the WIT `policy-context::bundle-handle` resource. |
| `src/epoch.rs` | `EpochId`, the monotonic loaded-module generation identifier. |
| `src/error.rs` | `WasmGuardError`, the fail-closed error vocabulary. |
| `src/host.rs` (`wasmtime-runtime`) | `WasmHostState`; core-module host functions and the WIT-generated `chio:guard@0.2.0` bindings, built from `wit/chio-guard/world.wit`. |
| `src/component.rs` (`wasmtime-runtime`) | `ComponentBackend`: evaluates Component Model guards through the bindgen'd `Guard` world. |
| `src/runtime/module.rs` | `LoadedModule`: one guard epoch's backend behind a `Mutex`, plus its manifest hash. |
| `src/runtime/guard.rs`, `src/runtime/evidence.rs` | `WasmGuard`: the `chio_kernel::Guard` adapter. `ArcSwap<LoadedModule>` reload, request translation, fail-closed evaluate, and `LastEvaluationEvidence` (crate-private) receipt metadata. |
| `src/runtime/backend.rs` | `WasmGuardRuntime`, an ordered collection of loaded guards. |
| `src/runtime/mock_backend.rs` (test / `test-support`) | `MockWasmBackend`, a fixed-verdict backend for tests. |
| `src/runtime/wasmtime_backend.rs` (`wasmtime-runtime`) | `WasmtimeBackend`, format detection, the per-tenant warm `InstancePre` pool, signed and policy-driven loading. |
| `src/wiring.rs` (`wasmtime-runtime`) | `load_wasm_guards` (`chio.yaml` loading) and `build_guard_pipeline` (HushSpec-then-WASM tier ordering). |
| `src/fuzz.rs` (`fuzz`) | libFuzzer entry points for the preinstantiate-validate and WIT host-call boundaries. |

## Evaluation and reload paths

`WasmGuard::evaluate`, called once per tool call from the kernel pipeline:

1. Build a `GuardRequest` from `GuardContext` via `extract_action_checked`;
   malformed arguments deny immediately, even for advisory guards.
2. Snapshot the current `LoadedModule` (`ArcSwap::load_full`) so a
   concurrent reload cannot change the epoch mid-evaluation.
3. Serialize the request to JSON, write it into guest memory (via the
   optional `chio_alloc` export, or offset 0), and call `evaluate` under
   the configured fuel limit.
4. Interpret the return value: `0` allows, `1` denies, anything else
   (including a trap or fuel exhaustion) is an error. A deny reads its
   reason from `chio_deny_reason`, or the legacy offset-64K
   NUL-terminated string.
5. Record fuel/epoch/hash evidence, emit verdict/duration/fuel metrics, and
   fail closed: a backend error denies unless the guard is advisory.

`hot_reload::Engine::reload_with_canary` / `reload_with_watchdog`:

1. Reject the replacement digest if it is in the `GuardDigestBlocklist`.
2. Build the replacement backend; canary-verified reloads must match all 32
   frozen `CanaryCorpus` fixtures before publishing.
3. Publish the new `LoadedModule` by swapping the `ArcSwap` pointer under a
   reload lock and reserving the next `EpochId`; evaluations already
   snapshotted on the old module keep running on it.
4. Watchdog-guarded reloads roll back via `ReloadWatchdog::record_error`
   once error-class verdicts exceed the configured threshold within the
   sliding window, and write a `ReloadIncident` to disk.

## Invariants and failure modes

- Every guest-facing failure (a trap, fuel exhaustion, a malformed return
  value, a serialization error, a missing export, an oversized module, or a
  forbidden import) becomes a typed `WasmGuardError`; the kernel adapter
  denies, or allows only when the guard is `advisory`.
- Core-module imports outside the `chio` namespace are rejected at
  `load_module` time, before instantiation.
- `verify_wit_world` and `verify_abi_version` reject anything but
  `chio:guard/guard@0.2.0` and `abi_version` `"1"`; there is no silent
  fallback to the prior 0.1.x world.
- Signing fails closed by default: no `signer_public_key` and no
  `allow_unsigned = true` refuses to load. A pinned key always requires a
  valid `.wasm.sig` sidecar; `allow_unsigned` cannot override it.
- Every reload entry point (`reload`, `reload_with_canary`,
  `reload_with_watchdog`, `reload_debounced`) checks the digest blocklist
  before building a replacement backend.
- Metric cardinality is bounded: guard/tenant IDs beyond
  `MAX_GUARD_METRIC_CARDINALITY` (1024) collapse into `__overflow__`; deny
  reasons collapse into one of nine `REASON_CLASS_*` values, never a
  free-form label.
- Tracing spans are pinned to the `chio.guard` target, not the emitting
  module's Rust path, so the CLI's default `chio.guard=info` filter enables
  them.
- The `WasmtimeBackend::evaluate` `InstancePre` checkout race against
  `Engine::reload`'s module swap is modeled under `loom`
  (`tests/loom_instance_pre_reload_vs_checkout.rs`); production modules are
  `cfg(not(loom))` and absent from that build.

## Dependencies

Internal:

- `chio-kernel` - the `Guard`, `GuardContext`, `GuardDecision`,
  `KernelError` contract this crate implements.
- `chio-guards` - `ToolAction` / `extract_action_checked`, enriching
  `GuardRequest` with an extracted action type, path, and target.
- `chio-config` - `WasmGuardEntry`, the `chio.yaml` schema consumed by
  `wiring::load_wasm_guards`.
- `chio-metrics-spec` - source of truth for Prometheus metric names and the
  live instrument registry incremented on evaluate, deny, and reload.
- `chio-core` - exercised only by this crate's test suites (`GuardContext`
  capability fixtures).

External:

- `wasmtime` / `wasmparser` (optional, `wasmtime-runtime`) - the WASM
  engine and format sniffer.
- `pollster` - bridges Wasmtime's async instantiate/call APIs into the
  synchronous `WasmGuardAbi::evaluate` contract.
- `ed25519-dalek` / `sha2` - manifest signature verification and digest
  hashing (module, blocklist, canary).
- `notify` / `tokio` - file watching and async orchestration for hot
  reload (debounced reload, registry polling).
- `arc-swap` - publishes module epochs without locking readers.

## Extension points

- `WasmGuardAbi` - add a runtime backend beyond `WasmtimeBackend` /
  `ComponentBackend`.
- `ReloadBackendFactory` - control how `hot_reload::Engine` compiles
  replacement module bytes (blanket-implemented for a matching closure).
- `RegistryDigestPoller` - drive reload triggers from an external
  registry's digest feed (blanket-implemented for a matching `FnMut`).
- `PlaceholderEnv` - source `${VAR}` guard-config values from something
  other than a `HashMap` or the process environment.
- `BundleStore` - back the WIT `policy-context::bundle-handle` resource
  with storage other than `InMemoryBundleStore`.
