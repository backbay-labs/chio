# chio-binding-helpers

`chio-binding-helpers` is a narrow Rust facade over `chio-core` and
`chio-manifest` that gives non-Rust Chio SDKs one byte-stable implementation
of the checks bindings must not re-derive: canonical JSON, SHA-256 hashing,
Ed25519 signing, and capability, receipt, and signed-manifest verification.
Each `verify_*` function returns a `serde`-serializable report struct rather
than a bare bool, so a binding can see exactly which check failed.

The crate holds no session, transport, auth, or orchestration state; that
stays in each language-native SDK under `sdks/`. `chio-bindings-ffi` exposes
this crate's surface over a C ABI for callers outside Rust.

## Responsibilities

- Canonicalize a raw JSON string to its RFC 8785 form (`canonicalize_json_str`).
- Parse and verify `CapabilityToken`s: signature, delegation-chain shape, and
  time status.
- Parse and verify `ChioReceipt`s: signature, action parameter hash,
  content-addressed receipt ID, decision/kind/boundary semantics, and
  (optionally) a trusted-signer set.
- Parse and verify `SignedManifest`s: structural validation, signature, and
  embedded-public-key-matches-signer.
- Provide SHA-256 hex digests and Ed25519 sign/verify over UTF-8 messages and
  canonical JSON strings, plus hex public-key/signature format checks.
- Own a stable, serializable `ErrorCode` enum so bindings can match on error
  kind instead of parsing Rust error strings.

## Public API

- `canonical::canonicalize_json_str`
- `capability::{parse_capability_json, verify_capability, verify_capability_json,
  capability_body_canonical_json}` - returns `CapabilityVerification` /
  `CapabilityTimeStatus`.
- `receipt::{parse_receipt_json, verify_receipt, verify_receipt_json,
  verify_receipt_with_trusted_signers, verify_receipt_with_trusted_signer_hex,
  verify_receipt_json_with_trusted_signer_hex, receipt_body_canonical_json}` -
  returns `ReceiptVerification` / `ReceiptDecisionKind`.
- `manifest::{parse_signed_manifest_json, verify_signed_manifest,
  verify_signed_manifest_json, signed_manifest_body_canonical_json}` - returns
  `ManifestVerification`.
- `hashing::{sha256_hex_bytes, sha256_hex_utf8}`
- `signing::{sign_utf8_message_ed25519, verify_utf8_message_ed25519,
  sign_json_str_ed25519, verify_json_str_signature_ed25519,
  is_valid_public_key_hex, is_valid_signature_hex, public_key_hex_matches}` -
  returns `Utf8MessageSignature` / `CanonicalJsonSignature`.
- `error::{Error, ErrorCode, Result}`

## Testing

`cargo test -p chio-binding-helpers` runs the per-module unit tests plus
`tests/vector_fixtures.rs`, which checks this crate's output against the
cross-language vector corpus in `tests/bindings/vectors/`. Fixture-regenerating
tests are `#[ignore]`d; run them with `-- --ignored` and refreeze the checksum
manifest with `cargo xtask freeze-vectors`.

## See also

- `chio-core` - supplies the capability, receipt, and crypto types this crate
  parses and verifies.
- `chio-manifest` - supplies `SignedManifest` and the validation/signing
  functions this crate wraps.
- `chio-bindings-ffi` - C ABI over this crate's surface for non-Rust callers.
