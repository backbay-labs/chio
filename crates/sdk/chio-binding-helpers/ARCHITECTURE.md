# chio-binding-helpers architecture

## Overview

`chio-binding-helpers` is a pure, deterministic library: no I/O, no session
state, no async runtime. It sits between `chio-core` and `chio-manifest`,
which own the protocol's capability, receipt, manifest, and cryptography
types, and the non-Rust Chio SDKs, which need the same verification results
as the Rust kernel without re-implementing Ed25519 signing or RFC 8785
canonical JSON. `chio-bindings-ffi` builds a C ABI on top of this crate for
callers outside Rust.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Declares the seven modules and re-exports their public items at the crate root. |
| `src/canonical.rs` | `canonicalize_json_str`, wrapping `chio_core::canonicalize`. |
| `src/hashing.rs` | `sha256_hex_bytes` / `sha256_hex_utf8`, wrapping `chio_core::sha256_hex`. |
| `src/signing.rs` | Ed25519 sign/verify over UTF-8 messages and canonical JSON strings; hex public-key and signature format checks. |
| `src/capability.rs` | `CapabilityToken` JSON parsing, canonical body JSON, and `verify_capability` (signature, delegation-chain shape, time status). |
| `src/receipt.rs` | `ChioReceipt` JSON parsing, canonical body JSON, `verify_receipt*` (signature, parameter hash, receipt ID, decision, trusted-signer authorization), and the human-readable `result` label. |
| `src/manifest.rs` | `SignedManifest` JSON parsing, canonical body JSON, and `verify_signed_manifest` (structure, signature, embedded-key-matches-signer). |
| `src/error.rs` | `Error` (wraps `chio_core::Error`, `serde_json::Error`, `chio_manifest::ManifestError`) and the `ErrorCode` each variant maps to. |

## Verification reports

Every `verify_*` function follows the same shape: parse or accept the
protocol type, run each check independently against `chio-core` /
`chio-manifest` primitives, and return a plain `serde`-serializable struct
with one field per check. Capability and manifest verification expose only
the per-check fields; receipt verification additionally folds them into
`authorized` and `ok` so a caller gets both the detail and one pass/fail bit.
No per-check field is computed conditionally on another, so a caller sees
every failure, not just the first.

## Invariants and failure modes

- Receipt `id` is bound into the signed payload: mutating `id` alone (without
  touching the body) invalidates both `receipt_id_valid` and `signature_valid`.
- An untrusted or empty signer set makes `authorized` and `ok` false even when
  signature, parameter hash, and receipt ID all check out; only an explicitly
  trusted `kernel_key` authorizes a receipt.
- `parse_trusted_signer_hex` fails closed on unparseable hex
  (`ErrorCode::InvalidHex`) instead of dropping the bad entry silently.
- `core_error_code` and the `ManifestError` arm in `Error::code` match every
  upstream variant explicitly, with no wildcard arm: a new `chio_core::Error`
  or `chio_manifest::ManifestError` variant is a compile error here until it
  is given a code.
- `tests/vector_fixtures.rs` treats the on-disk JSON under
  `tests/bindings/vectors/` as ground truth; the in-Rust fixture builders are
  regenerators, not the source of truth, and stay behind `#[ignore]`.

## Dependencies

Internal: `chio-core` supplies `CapabilityToken`, `ChioReceipt`, the crypto
primitives (`Keypair`, `PublicKey`, `Signature`), canonical JSON
(`canonicalize`, `canonical_json_string`), and `sha256_hex`. `chio-manifest`
supplies `SignedManifest`, `ToolManifest`, `validate_manifest`, and
`sign_manifest`. External: `serde` / `serde_json` for parsing and the
serializable report structs, `thiserror` for `Error`. Dev-only:
`chio-test-support` (`TestUnwrap`) in the vector-fixture integration test.
