# chio-bindings-ffi architecture

## Overview

`chio-bindings-ffi` is the trust boundary between an untrusted C or C++
caller and `chio-binding-helpers`, which owns all canonicalization, hashing,
signing, and verification semantics. It holds none of that logic itself:
every result comes from a `chio-binding-helpers` call, and this crate's job
is to validate pointers on the way in and guarantee that no Rust panic or
invalid buffer crosses the ABI on the way out. It is a `staticlib` /
`cdylib` / `rlib` (`crate-type` in `Cargo.toml`); `sdks/cpp/chio-cpp` links
the static library and compiles against the checked-in header.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | All exported C symbols, `ChioFfiBuffer`/`ChioFfiResult`, pointer and UTF-8 validation, panic containment, `chio-binding-helpers` calls, FFI error-code mapping, and the `#[cfg(test)]` round-trip and symbol-snapshot tests. |
| `cbindgen.toml` | cbindgen config: C header, `pragma once`, C++-compatible style, and an explicit export allowlist. |
| `include/chio/chio_ffi.h` | Checked-in header generated from this crate's exports. Not produced by a `build.rs`; `scripts/check-chio-cpp.sh` regenerates it with `cbindgen` and diffs against this copy. |

## Request lifecycle

1. A caller passes NUL-terminated UTF-8 strings as `*const c_char` (every
   function except `chio_sha256_hex_bytes`, which takes `*const u8` +
   `usize`, and `chio_buffer_free`, which takes a `ChioFfiBuffer` by value).
   `read_c_str` rejects a null pointer (`CHIO_FFI_STATUS_NULL_ARGUMENT`) and
   invalid UTF-8 (`CHIO_FFI_STATUS_ERROR`) before any parsing; `read_bytes`
   rejects a null pointer with non-zero length the same way and treats a
   null pointer with zero length as an empty buffer.
2. Each fallible entry point's body runs inside `run_ffi`, which wraps it in
   `catch_unwind(AssertUnwindSafe(f))`. A panic anywhere in the call becomes
   `CHIO_FFI_STATUS_PANIC` instead of unwinding across the C ABI.
3. The validated input is handed to the matching `chio-binding-helpers`
   function (`canonicalize_json_str`, `sha256_hex_utf8`,
   `sign_utf8_message_ed25519`, `verify_capability_json`,
   `verify_receipt_json_with_trusted_signer_hex`, and so on), which owns all
   parsing, canonicalization, hashing, signing, and verification logic.
4. A success value becomes a `String` (directly for hashes and signatures,
   through the local `json()` helper for structured results) and is boxed
   into a `ChioFfiBuffer`. A `chio_binding_helpers::Error` is mapped through
   `ffi_error_code_from_helper_code` to a stable `CHIO_FFI_ERROR_*` integer,
   and its `Display` message becomes the buffer instead.
5. The caller reads `status` / `error_code` / `data` and must pass any
   non-empty `data` buffer to `chio_buffer_free` exactly once.

## Unsafe boundary

Three `unsafe` blocks in `src/lib.rs`, all `SAFETY`-commented:

- `read_c_str` calls `CStr::from_ptr(ptr)` after checking the pointer is
  non-null, trusting the caller's promise of a valid NUL-terminated string.
  Every `*const c_char` parameter in this crate is read through this helper.
- `read_bytes` calls `slice::from_raw_parts(ptr, len)` after checking `ptr`
  is non-null whenever `len != 0`, trusting the caller's promise of `len`
  readable bytes. `chio_sha256_hex_bytes` is its only caller.
- `chio_buffer_free` calls `Vec::from_raw_parts(buffer.ptr, buffer.len,
  buffer.len)` directly, not through a helper, to reclaim a buffer this
  crate previously leaked via `mem::forget` on a boxed slice in
  `ChioFfiBuffer::from_bytes`. Passing a foreign, already-freed, or
  length-mismatched buffer here is undefined behavior, as with any C ABI
  ownership handoff.

None of the fourteen exported `extern "C"` functions is itself declared
`unsafe fn`. Each pushes its pointer dereferencing into one of the three
blocks above, behind an explicit null check.

## Invariants and failure modes

- Every fallible exported function fails closed: null pointers, invalid
  UTF-8, malformed JSON, malformed hex, and internal panics all return a
  non-OK `ChioFfiResult` rather than a partial buffer.
- `chio_verify_receipt_json` always verifies against an empty trusted-signer
  set (`chio_binding_helpers::verify_receipt` calls
  `verify_receipt_with_trusted_signers(receipt, &[])`), so `signer_trusted`,
  `authorized`, and `ok` are structurally `false` regardless of the
  receipt's cryptographic validity.
  `chio_verify_receipt_json_with_trusted_signers` is the only entry point
  that can report `authorized: true`.
- `chio_verify_capability_json` maps `max_delegation_depth ==
  CHIO_FFI_NO_MAX_DELEGATION_DEPTH` (`u32::MAX`) to `None` (no limit), not to
  a literal depth cap of `u32::MAX`.
- ABI stability: exported symbol names are pinned by
  `tests/abi/chio-bindings-ffi.symbols`. The numeric `CHIO_FFI_STATUS_*` and
  `CHIO_FFI_ERROR_*` values are pinned because
  `sdks/cpp/chio-cpp/include/chio/result.hpp` defines a C++ `ErrorCode` enum
  using the same integers (`0`-`28`, `255`) that `invariants.cpp` casts FFI
  error integers into; a new FFI error integer must use a
  previously-unused value.
- The ABI carries no async flows, callbacks, session state, or transport
  state. Every exported function other than `chio_buffer_free` is a
  synchronous, side-effect-free computation over its arguments.

## Dependencies

`chio-binding-helpers` supplies every canonicalization, hashing, signing,
and verification behavior this crate calls; this crate defines none of that
logic itself and has no direct dependency on `chio-core` or `chio-manifest`
(both are reached transitively through `chio-binding-helpers`). `serde` and
`serde_json` serialize the FFI-only `BuildInfo` struct and decode the
`trusted_signers_json` argument. No dependency is aliased:
`chio_binding_helpers::` in source matches the crate name directly.
