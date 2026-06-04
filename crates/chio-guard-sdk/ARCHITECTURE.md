# chio-guard-sdk Architecture

`chio-guard-sdk` is the guest-side Rust SDK for authoring Chio WASM guards that
target the `chio:guard@0.2.0` ABI. It owns the guard-author API, the JSON ABI
types shared with the host runtime, the guest linear-memory allocator exports,
and the glue that turns guest verdicts into host-visible return codes and deny
reasons.

## Boundaries

- `chio-wasm-guards` owns host-side module loading, memory writes, fuel metering,
  and interpretation of guest return codes.
- `chio-guard-sdk-macros` owns generation of the exported `evaluate` entry point
  and re-exports this crate's allocator and deny-reason functions.
- `sdks/rust/chio-guard-sdk-compat` is a compatibility facade over this crate.
- This crate owns the guest API, serde field shape, native-test fallbacks for
  host imports, `PolicyContext` handle wrapper, `chio_alloc`/`chio_free`, request
  deserialization, verdict encoding, and structured deny-reason serialization.

## Trust Invariants

- `GuardRequest` serde annotations must stay byte-compatible with the host-side
  `chio-wasm-guards` ABI.
- Native targets never call WASM host imports; wrappers return no-op or
  unavailable results so guard logic can be tested without a runtime.
- `read_request` rejects zero or negative pointers and negative lengths before
  constructing a raw memory slice.
- Deny verdicts exposed through `encode_verdict` always carry a non-empty reason;
  blank or whitespace-only reasons are replaced with a stable fallback.
- `chio_alloc` returns 0 for non-positive sizes, and `chio_free` treats invalid
  pointers as no-ops because the host still validates guest memory bounds.
- `PolicyContext` exposes the host-provided bundle handle without taking
  ownership of resource reclamation.

## Testing Focus

Unit tests cover ABI constants, request serde defaults and omitted fields,
verdict encoding, deny-reason serialization, bad request pointer and length
guards, native host-wrapper fallbacks, policy-context reads, and allocator
edge cases. Macro-level export generation is covered in `chio-guard-sdk-macros`.
