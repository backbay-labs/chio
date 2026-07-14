# chio-cpp-kernel-ffi architecture

## Overview

`chio-cpp-kernel-ffi` is the trust boundary between an untrusted C++ caller
and `chio-kernel-core`, which owns capability evaluation, verification, and
receipt signing. It holds no evaluation or signing logic of its own: every
verdict, signature, and verification result is produced by a `chio-kernel-core`
call, and this crate's job is to validate the request on the way in and
guarantee that no Rust panic or invalid buffer crosses the C ABI on the way
out. It is a `staticlib`/`cdylib`/`rlib` (`crate-type` in `Cargo.toml`), built
both to link into C++ and to be included as a Rust source module by
`cross_ffi_parity.rs` for direct comparison against `chio-kernel-mobile`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | All exported C symbols, request/response envelopes, pointer and UTF-8 validation, panic containment, `chio-kernel-core` calls, and FFI error mapping. |
| `src/tests.rs` (`#[cfg(test)]`) | Regression tests over both the internal `*_json_str` helpers and the public `extern "C"` symbols. |
| `cbindgen.toml` | cbindgen config: C header, `pragma once`, C++-compatible style, and an explicit export allowlist. |
| `include/chio/chio_kernel_ffi.h` | Checked-in header generated from this crate's exports; `sdks/cpp/chio-cpp-kernel` compiles against it directly. |

## Request lifecycle

1. A C caller passes NUL-terminated UTF-8 JSON (and hex) strings as `*const
   c_char`. `read_c_str` rejects null pointers
   (`CHIO_KERNEL_FFI_STATUS_NULL_ARGUMENT`) and invalid UTF-8
   (`CHIO_KERNEL_FFI_ERROR_INVALID_JSON`) before any parsing happens.
2. Each entry point's body runs inside `run_ffi`, which wraps it in
   `catch_unwind`. A panic anywhere in the call becomes
   `CHIO_KERNEL_FFI_STATUS_PANIC` instead of unwinding across the C ABI.
3. The JSON envelope is deserialized and caller-supplied trust data is
   validated before it can influence a verdict: `capability_trust_roots`
   issuer keys must decode as hex public keys and their scope hashes must be
   non-empty, unpadded, and control-character-free; `parent_budget_snapshots`
   token IDs must be non-empty and unpadded.
4. The validated request is handed to `chio-kernel-core`
   (`evaluate_with_full_floor`, `verify_capability_full`, `sign_receipt`,
   `sign_receipt_relaying_trusted_body`, `passport_verify::verify_passport`),
   which owns all evaluation, chain-binding, budget-split, and cryptographic
   semantics.
5. The result is serialized to JSON, moved into a boxed byte slice, and
   returned as a `ChioKernelFfiBuffer` the caller must pass to
   `chio_kernel_buffer_free`. `chio-kernel-core` error types are mapped to a
   `KernelFfiError` variant and a stable `error_code` integer.

## Unsafe boundary

Two `unsafe` blocks in `src/lib.rs`, both `SAFETY`-commented:

- `read_c_str` calls `CStr::from_ptr(ptr)` on a caller-supplied pointer,
  trusting the C caller's promise of a valid NUL-terminated string. This runs
  only after the pointer has been checked non-null.
- `chio_kernel_buffer_free` calls `Vec::from_raw_parts(buffer.ptr, buffer.len,
  buffer.len)` to reclaim a buffer this crate previously leaked via
  `Box::into_raw`-equivalent (`std::mem::forget` on a boxed slice) in
  `ChioKernelFfiBuffer::from_string`. Passing a foreign or already-freed
  buffer here is undefined behavior, as with any C ABI ownership handoff.

All request parsing, validation, JSON handling, and kernel-core calls are
safe Rust; `unsafe` is confined to the two raw-pointer crossings above.

## Invariants and failure modes

- Every exported function fails closed: malformed JSON, invalid hex, invalid
  capability or passport shape, untrusted issuers, expired or not-yet-valid
  tokens, oversubscribed sibling budgets, and internal panics all return a
  non-OK `ChioKernelFfiResult` rather than a partial result.
- `chio_kernel_sign_receipt_json` is the default signer and is WYSIWYS: it
  recomputes `content_hash` over the caller-supplied canonical content
  preimage and refuses to sign (`CHIO_KERNEL_FFI_ERROR_SIGNING_FAILED`) on a
  mismatch. `chio_kernel_sign_receipt_relaying_trusted_body_json` is a
  separate, explicitly named relay seam that trusts `body.content_hash`
  as-is; it exists only to forward a body an upstream trusted producer
  already minted.
- `Verdict::PendingApproval` from `chio-kernel-core` has no representation in
  this ABI's synchronous request/response shape; `chio_kernel_evaluate_json`
  downgrades it to `deny` with an explanatory reason instead of exposing an
  async approval flow.
- A change to any exported symbol's argument shape must bump
  `CHIO_CPP_KERNEL_FFI_ABI_VERSION`, so a client gating on
  `chio_kernel_ffi_abi_version()` fails closed instead of calling a stale
  symbol with mismatched arguments.
- The ABI is synchronous and buffer-based only. There are no callbacks,
  async handles, transport state, or kernel sessions crossing it, and no
  async runtime dependency in `Cargo.toml`.
- `chio_kernel_evaluate_json` always calls `evaluate_with_full_floor` with an
  empty `guards` slice and `session_filesystem_roots: None`. Verdicts
  returned over this ABI reflect capability scope, expiry, and chain-binding
  only; no `Guard` pipeline plugin and no filesystem-root scoping run on this
  path.

## Dependencies

`chio-kernel-core` supplies all evaluation, capability verification, budget
registry, and receipt-signing/passport logic; this crate calls it but defines
none of that logic itself. `chio-core-types` supplies the wire types
(`CapabilityToken`, `Keypair`, `ChioReceiptBody`, `ScopeHash`, ...) the JSON
envelopes deserialize into. `hex` and `serde`/`serde_json` handle encoding at
the boundary. No dependency is aliased: `chio_core_types::` and
`chio_kernel_core::` in source match their crate names directly.
