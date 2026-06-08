# chio-wasm-guards Architecture Notes

## Module Boundaries

`src/lib.rs` is the crate API root and feature-gated module index. Runtime
implementation lives under `src/runtime/` instead of the runtime module root:
`module.rs` owns loaded module epochs and backend locking, `evidence.rs` owns
last-evaluation receipt metadata, `guard.rs` owns `WasmGuard` and its
`chio_kernel::Guard` adapter, `backend.rs` owns the `WasmGuardRuntime`
collection and backend-factory loading, `mock_backend.rs` owns the deterministic
test backend, and `wasmtime_backend.rs` owns the default Wasmtime runtime,
format detection, policy-driven loading, signature enforcement, import checks,
fuel accounting, memory limits, deny-reason extraction, and instance-pre pool.

The existing `abi.rs` remains the backend trait and guest request/verdict ABI
boundary. `host.rs` remains the Wasmtime host-function binding and host-state
boundary. `component.rs` remains the Component Model backend. `hot_reload.rs`
owns reload orchestration, canary checks, rollback, reload triggers, and
incident emission. `wiring.rs` owns conversion from configuration entries into
kernel guard pipelines.

## Feature Boundaries

The `wasmtime-runtime` feature gates the Wasmtime backend, Component Model
support, host bindings, and production guard wiring. Backend-free builds keep
the ABI, config, manifest, hot-reload types, mock backend, and kernel adapter
available for tests or alternative runtimes. The `fuzz` feature depends on
`wasmtime-runtime` because pre-instantiation validation is implemented in the
Wasmtime backend boundary.

## Security Constraints

Runtime splitting must not change guard verdict semantics, fuel accounting,
manifest hash evidence, epoch assignment, signature verification, WIT world
validation, import allowlisting, memory limits, or fail-closed behavior. Any
backend load, trap, malformed action extraction, module-size violation, import
violation, signature failure, or unsupported format continues to deny or reject
before guest code can silently allow.
