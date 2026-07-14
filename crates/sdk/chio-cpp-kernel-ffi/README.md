# chio-cpp-kernel-ffi

C ABI for the Chio C++ offline kernel SDK. `chio-cpp-kernel-ffi` wraps
`chio-kernel-core`'s capability evaluation, capability verification, receipt
signing, and passport verification behind a plain `extern "C"` surface: JSON
strings in, JSON strings out, Rust-owned buffers the caller must free
explicitly. It mirrors `chio-kernel-mobile`'s JSON-in/JSON-out shape but skips
UniFFI, so the generated header carries no Rust or UniFFI concepts into C++.

Distinct from `chio-bindings-ffi`: that crate exposes `chio-binding-helpers`'
stateless invariant checks (signature, manifest, and capability-shape
validation) to `sdks/cpp/chio-cpp`. This crate exposes kernel *evaluation*
(capability-scoped verdicts, receipt signing, chain-bound capability
verification) to the separate offline kernel library
`sdks/cpp/chio-cpp-kernel`.

## Responsibilities

- Evaluate a portable tool-call request against a capability token via
  `chio_kernel_core::evaluate_with_full_floor`, returning an allow/deny
  verdict as JSON (`chio_kernel_evaluate_json`).
- Sign receipt bodies through the default WYSIWYS path, which recomputes
  `content_hash` over a caller-supplied canonical preimage and refuses to
  sign on mismatch (`chio_kernel_sign_receipt_json`), plus an explicit relay
  seam for forwarding an already-minted trusted body
  (`chio_kernel_sign_receipt_relaying_trusted_body_json`).
- Verify capability tokens, either against a single trusted authority
  (`chio_kernel_verify_capability_json`) or with full context: peer feature
  negotiation, per-issuer trust roots, and parent-budget snapshots for
  delegated tokens (`chio_kernel_verify_capability_with_context_json`).
- Verify portable-passport envelopes (`chio_kernel_verify_passport_json`).
- Validate every pointer, UTF-8 string, and hex field at the boundary, and
  contain panics so nothing but a defined `ChioKernelFfiResult` ever crosses
  back into C++.

## Public API

`extern "C"` functions (`#[no_mangle]`), all declared in `src/lib.rs`:

| Function | Purpose |
|----------|---------|
| `chio_kernel_ffi_abi_version()` | Returns `CHIO_CPP_KERNEL_FFI_ABI_VERSION` (currently `2`). |
| `chio_kernel_build_info()` | Crate name, crate version, ABI version, and target triple as JSON. |
| `chio_kernel_buffer_free(buffer)` | Releases a `ChioKernelFfiBuffer` previously returned by this crate. |
| `chio_kernel_evaluate_json(request_json)` | Evaluate a tool-call request; `PendingApproval` verdicts come back as `deny` (no async approval path over this ABI). |
| `chio_kernel_sign_receipt_json(body_json, canonical_content_hex, signing_seed_hex)` | Default WYSIWYS signer. |
| `chio_kernel_sign_receipt_relaying_trusted_body_json(body_json, signing_seed_hex)` | Relay signer; trusts `body.content_hash` as-is. |
| `chio_kernel_verify_capability_json(token_json, authority_pub_hex, now_secs)` | Single-authority verification. |
| `chio_kernel_verify_capability_with_context_json(request_json)` | Full-context verification (trust roots, peer profile, budget snapshots). |
| `chio_kernel_verify_passport_json(envelope_json, issuer_pub_hex, now_secs)` | Passport envelope verification. |

Every JSON-returning function returns `ChioKernelFfiResult { status,
error_code, data: ChioKernelFfiBuffer }`. `status` is one of
`CHIO_KERNEL_FFI_STATUS_{OK, ERROR, PANIC, NULL_ARGUMENT}`; `error_code` is
one of `CHIO_KERNEL_FFI_ERROR_{NONE, INVALID_JSON, INVALID_HEX,
INVALID_CAPABILITY, INVALID_PASSPORT, KEY_MISMATCH, SIGNING_FAILED,
INTERNAL}`. The full set of exported names is enumerated in `cbindgen.toml`
and the generated `include/chio/chio_kernel_ffi.h`.

## Testing

- `cargo test -p chio-cpp-kernel-ffi` runs `src/tests.rs`: pointer and UTF-8
  handling, evaluation allow/deny paths, delegated-budget admission and
  oversubscription rejection, malformed trust-root rejection, WYSIWYS
  accept/refuse (including a simulated render-A/sign-B forgery), the relay
  seam, and the ABI version regression check.
- `crates/kernel/chio-kernel-mobile/tests/cross_ffi_parity.rs` includes this
  crate's `src/lib.rs` directly and compares `chio_kernel_evaluate_json`
  against `chio-kernel-mobile`'s `evaluate` for shared verdict cases.
- `sdks/cpp/chio-cpp-kernel/scripts/check-with-ffi.sh` builds and tests this
  crate, then configures, builds, and CTests the C++ SDK against the
  resulting static library and `include/chio/chio_kernel_ffi.h`.

## See also

- `chio-kernel-core` - owns all evaluation, verification, and signing
  semantics this crate calls into.
- `chio-kernel-mobile` - the UniFFI (Swift/Kotlin) counterpart; cross-checked
  against this crate by `cross_ffi_parity.rs`.
- `chio-bindings-ffi` - a separate C ABI over `chio-binding-helpers`'
  stateless invariant checks, consumed by `sdks/cpp/chio-cpp`. Not a kernel
  and not interchangeable with this crate.
- `sdks/cpp/chio-cpp-kernel` - the C++ wrapper that links this crate's static
  library against its generated header.
