# chio-cpp-kernel-ffi Architecture

`chio-cpp-kernel-ffi` owns the plain C ABI for the Chio C++ offline kernel
package. It is a narrow JSON-in, JSON-out bridge over `chio-kernel-core` and
`chio-core-types`; it must not grow into a session runtime, transport layer, or
policy engine.

## Boundaries

- `src/lib.rs` owns all exported C symbols, pointer and UTF-8 validation, JSON
  request parsing, kernel-core calls, Rust-owned response buffers, and FFI error
  mapping.
- `include/chio/chio_kernel_ffi.h` is the checked-in C header generated from
  this crate's public exports and `cbindgen.toml`.
- `sdks/cpp/chio-cpp-kernel` owns the C++ wrapper and request-builder surface.
- `chio-kernel-core` owns capability verification, portable evaluation,
  budget-split enforcement, passport verification, and receipt signing
  semantics.

## Pain Points

- The FFI accepts rich JSON envelopes for evaluation and contextual capability
  verification. That is the right ABI shape, but it means trust-bearing maps
  and budget snapshots need explicit validation at the FFI boundary.
- `capability_trust_roots` is keyed by issuer public-key hex. Malformed keys
  are not useful trust roots and should not be silently ignored just because a
  specific token path does not consult them.
- `ScopeHash` is currently a string alias, so empty or padded root hashes need
  local validation before they participate in chain-binding decisions.

## Security And API Constraints

- Malformed trusted issuer keys, trust-root keys, trust-root scope hashes,
  capability tokens, passport envelopes, receipt bodies, and signing seeds must
  fail closed with stable FFI error codes.
- Existing ABI version, exported symbols, status codes, and error code integers
  must remain stable unless an explicit ABI migration is planned.
- The C ABI remains synchronous and buffer-based. Do not expose callbacks,
  async handles, transport state, or kernel sessions here.
- Core verification semantics must remain delegated to `chio-kernel-core`.

## Affected Dependents

- `sdks/cpp/chio-cpp-kernel` receives the same exported symbols and request
  shape. Valid requests are unchanged.
- `chio-kernel-core` remains the semantic verifier; this crate only rejects
  malformed FFI configuration before calling into it.
- The generated C header is unaffected by this validation-only slice.

## Planned Improvement

Validate `capability_trust_roots` before portable evaluation or contextual
capability verification. Every trust-root map key must decode as a public key,
and every root scope hash must be non-empty, unpadded, and control-free.
