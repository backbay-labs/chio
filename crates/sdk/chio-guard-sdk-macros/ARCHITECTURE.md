# chio-guard-sdk-macros Architecture

`chio-guard-sdk-macros` owns the `#[chio_guard]` attribute macro used by Rust
guest guards. The macro turns a plain guard-author function into the exported
WASM ABI surface expected by `chio-wasm-guards`.

## Boundaries

- `chio-guard-sdk` owns runtime ABI types, request decoding, verdict encoding,
  allocator exports, and structured deny-reason serialization.
- `chio-wasm-guards` owns host-side module loading, memory writes, fuel metering,
  and interpretation of the exported `evaluate` function.
- This crate owns compile-time validation of the annotated function shape and
  generated Rust tokens that re-export SDK glue into the final WASM artifact.

## Trust Invariants

- The macro accepts only a plain `fn evaluate(req: GuardRequest) -> GuardVerdict`.
- Async, const, unsafe, extern, generic, variadic, method, missing-argument, and
  wrong-return signatures are rejected at macro expansion time.
- The generated export is always `#[no_mangle] pub extern "C" fn evaluate(ptr:
  i32, len: i32) -> i32`.
- Bad request decoding fails closed by returning `VERDICT_DENY`.
- Guard verdicts are encoded only through `chio_guard_sdk::encode_verdict`, so
  deny-reason normalization stays centralized in the SDK crate.

## Testing Focus

Unit tests cover the pure signature validator. Downstream example guard crates
cover generated-token compilation through the normal workspace check.
