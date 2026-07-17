# chio-bindings-ffi

C ABI over `chio-binding-helpers`'s deterministic invariant checks: canonical
JSON, SHA-256 hashing, Ed25519 signing and verification, and capability,
receipt, and manifest verification. Builds as `staticlib`, `cdylib`, and
`rlib` (`crate-type` in `Cargo.toml`) so a non-Rust SDK can link it directly;
`sdks/cpp/chio-cpp/src/invariants.cpp` is the crate's consumer, calling these
functions through the generated header.

Distinct from `chio-cpp-kernel-ffi`: that crate wraps `chio-kernel-core` and
evaluates tool-call requests, signs receipts, and verifies capabilities with
full trust-root and budget context. This crate wraps `chio-binding-helpers`
only. It performs no kernel evaluation and holds no session, transport, or
runtime state; every call is a synchronous function of its arguments.

## Responsibilities

- Expose `chio-binding-helpers`'s invariant checks as `extern "C"` functions:
  JSON canonicalization, hashing, Ed25519 sign/verify, and capability,
  receipt, and manifest verification.
- Validate every raw pointer and UTF-8 string at the boundary before it
  reaches Rust logic, and translate `chio_binding_helpers::Error` into a
  stable `ChioFfiResult` status and numeric error code.
- Contain panics (`catch_unwind`) so a Rust panic never unwinds across the C
  ABI.
- Own the buffer contract: allocate `ChioFfiBuffer`s the caller must release
  through `chio_buffer_free`.

## Public API

Two `#[repr(C)]` types carry every result: `ChioFfiBuffer { ptr, len }` and
`ChioFfiResult { status, error_code, data }`. Exported `extern "C"` functions
(`src/lib.rs`):

| Function | Purpose |
|----------|---------|
| `chio_ffi_abi_version()` | Returns `CHIO_FFI_ABI_VERSION` (currently `1`) as a plain `u32`. |
| `chio_buffer_free(buffer)` | Releases a `ChioFfiBuffer` previously returned by this crate; returns nothing. No-op on a null pointer or zero length. |
| `chio_ffi_build_info()` | Crate name, crate version, ABI version, and target triple as JSON (`features` is always an empty array; the crate defines no Cargo features). |
| `chio_canonicalize_json(input_json)` | RFC 8785 canonical JSON. |
| `chio_sha256_hex_utf8(input_utf8)` / `chio_sha256_hex_bytes(input, input_len)` | SHA-256 hex digest of a UTF-8 string or a raw byte buffer. |
| `chio_sign_utf8_message_ed25519(input_utf8, seed_hex)` / `chio_verify_utf8_message_ed25519(input_utf8, public_key_hex, signature_hex)` | Ed25519 sign/verify over a raw UTF-8 message. |
| `chio_sign_json_ed25519(input_json, seed_hex)` / `chio_verify_json_signature_ed25519(input_json, public_key_hex, signature_hex)` | Ed25519 sign/verify over canonical JSON. |
| `chio_verify_capability_json(input_json, now_secs, max_delegation_depth)` | Capability chain verification; pass `CHIO_FFI_NO_MAX_DELEGATION_DEPTH` for no depth limit. |
| `chio_verify_receipt_json(input_json)` | Receipt verification with an empty trusted-signer set; `authorized` and `ok` are always `false`. |
| `chio_verify_receipt_json_with_trusted_signers(input_json, trusted_signers_json)` | Receipt verification against a JSON array of trusted signer public keys. The only entry point that can report `authorized: true`. |
| `chio_verify_manifest_json(input_json)` | Signed manifest verification. |

The twelve functions other than `chio_buffer_free` and `chio_ffi_abi_version`
return `ChioFfiResult`, with `status` one of `CHIO_FFI_STATUS_{OK, ERROR,
PANIC, NULL_ARGUMENT}` and, on failure, `error_code` set to one of the
`CHIO_FFI_ERROR_*` constants. Each `chio_binding_helpers::ErrorCode` variant
maps to exactly one `CHIO_FFI_ERROR_*` constant; `NONE` and `INTERNAL` (255)
are FFI-only, covering success and boundary failures (bad UTF-8, null
arguments, panics) that never reach `chio-binding-helpers`. The generated
`include/chio/chio_ffi.h` and `cbindgen.toml`'s export allowlist enumerate
the full symbol and constant set.

## Testing

`cargo test -p chio-bindings-ffi` runs the C-ABI round-trip tests in
`src/lib.rs`, including a symbol-snapshot test that pins the exported
function list against `tests/abi/chio-bindings-ffi.symbols`.
`scripts/check-chio-cpp.sh` additionally regenerates `chio_ffi.h` with
`cbindgen`, diffs it against the checked-in copy, and builds and CTests
`sdks/cpp/chio-cpp` against this crate's static library.

## See also

- `chio-binding-helpers` - owns the invariant-check semantics this crate
  exposes over C.
- `chio-cpp-kernel-ffi` - the sibling C ABI for kernel evaluation; not
  interchangeable with this crate.
- `sdks/cpp/chio-cpp` - the C++ SDK that links this crate's static library
  and generated header.
