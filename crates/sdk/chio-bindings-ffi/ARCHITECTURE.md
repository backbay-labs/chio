# chio-bindings-ffi Architecture

## Owner

`chio-bindings-ffi` owns the stable C ABI for deterministic SDK invariant helpers. It is a thin ABI layer over `chio-binding-helpers`, not a runtime, transport, session, or kernel crate.

## Module Boundaries

This crate has one Rust module because the surface is intentionally small:

- exported C functions accept UTF-8 C strings or raw byte buffers
- helper code validates pointers and UTF-8 before crossing into `chio-binding-helpers`
- all successful outputs are UTF-8 buffers allocated by Rust
- all failures return `ChioFfiResult` with stable status and error-code integers
- callers must release non-empty returned buffers with `chio_buffer_free`

The checked-in C header under `include/chio/chio_ffi.h` is an ABI artifact generated from this crate's Rust exports and `cbindgen.toml`. The symbol snapshot under `tests/abi/` is the review gate for exported names.

## Design Constraints

- Passing arrays through C would create ownership and lifetime hazards. This ABI deliberately prefers JSON-string parameters for structured inputs.
- Header and symbol artifacts must move with the Rust export to avoid ABI drift.
- `chio_verify_receipt_json_with_trusted_signers` is the authoritative receipt-verification entrypoint: it accepts a receipt JSON string plus a trusted-signer JSON array. Without a trusted signer set, callers observe only cryptographic validity, not authoritative receipt trust.

## Security And API Constraints

- Receipt authorization must require an explicit trusted signer set.
- Malformed trusted signer input must fail closed with a stable FFI error result.
- Existing ABI v1 symbols and numeric status/error-code values must remain stable.
- Do not expose async flows, callbacks, session state, transport state, or kernel execution.
- Do not hand-edit generated header semantics independently from the Rust export and cbindgen config.

## Affected Dependents

The C++ SDK consumes this crate through `sdks/cpp/chio-cpp/src/invariants.cpp`. The FFI error codes (including manifest validation codes 22 through 28) are named by the C++ `ErrorCode` enum in `sdks/cpp/chio-cpp/include/chio/result.hpp`, which `invariants.cpp` casts FFI error integers into. New FFI error integers must stay numerically stable so the C++ enum mapping holds.
