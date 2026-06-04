# Chio Bindings API Contract

## Purpose

Freeze the initial `chio-binding-helpers` boundary so SDK work can proceed without turning the bindings layer into a second runtime.

This document is intentionally small. It describes the current contract that SDKs may rely on during the SDK parity roadmap.

## Scope

`chio-binding-helpers` is the bindings-friendly Rust facade for deterministic invariant logic only.

It is allowed to own:

- canonical JSON helpers
- hashing helpers
- signing and verification helpers
- receipt parsing and verification helpers
- capability parsing and verification helpers
- signed manifest parsing and verification helpers
- stable bindings-oriented error codes

It is not allowed to own:

- session state machines
- remote HTTP or stream transports
- auth discovery, OAuth, token exchange, or token providers
- task orchestration
- nested callback routers
- trust-control service clients
- kernel execution runtime

## Current Public Surface

The current public export surface is:

### Canonical JSON

- `canonicalize_json_str`

### Hashing

- `sha256_hex_bytes`
- `sha256_hex_utf8`

### Signing

- `is_valid_public_key_hex`
- `is_valid_signature_hex`
- `public_key_hex_matches`
- `sign_utf8_message_ed25519`
- `verify_utf8_message_ed25519`
- `sign_json_str_ed25519`
- `verify_json_str_signature_ed25519`
- `Utf8MessageSignature`
- `CanonicalJsonSignature`

### Receipts

- `parse_receipt_json`
- `receipt_body_canonical_json`
- `verify_receipt`
- `verify_receipt_json`
- `verify_receipt_with_trusted_signers`
- `verify_receipt_with_trusted_signer_hex`
- `verify_receipt_json_with_trusted_signer_hex`
- `ReceiptDecisionKind`
- `ReceiptVerification`

### Capabilities

- `parse_capability_json`
- `capability_body_canonical_json`
- `verify_capability`
- `verify_capability_json`
- `CapabilityTimeStatus`
- `CapabilityVerification`

### Signed manifests

- `parse_signed_manifest_json`
- `signed_manifest_body_canonical_json`
- `verify_signed_manifest`
- `verify_signed_manifest_json`
- `ManifestVerification`

### Errors

- `Error`
- `ErrorCode`
- `Result<T>`

## Stable Error Taxonomy

The current stable bindings error codes are:

- `invalid_public_key`
- `invalid_hex`
- `invalid_signature`
- `json`
- `canonical_json`
- `capability_expired`
- `capability_not_yet_valid`
- `capability_revoked`
- `delegation_chain_broken`
- `attenuation_violation`
- `scope_mismatch`
- `signature_verification_failed`
- `delegation_depth_exceeded`
- `invalid_hash_length`
- `merkle_proof_failed`
- `empty_tree`
- `invalid_proof_index`
- `empty_manifest`
- `duplicate_tool_name`
- `invalid_tool_name`
- `invalid_input_schema`
- `invalid_output_schema`
- `duplicate_server_tool`
- `unsupported_schema`
- `manifest_verification_failed`

SDKs should depend on the serialized snake_case code values rather than Rust enum spelling.

## Input And Output Rules

The bindings contract should prefer:

- JSON-string input for structured payloads
- UTF-8 string input for signed text helpers
- byte-slice input only where byte identity is the point of the helper
- explicit verification result structs rather than raw booleans when policy or receipt detail matters

The bindings contract should avoid:

- exposing deep internal Rust types directly
- opaque handles unless they are clearly reusable compiled objects
- async APIs
- ownership-sensitive runtime state

## Change Rules

The contract is considered frozen under the following rules:

1. New public entrypoints require an owning vector, unit test, or both.
2. Changes that widen scope into transport or runtime behavior should be rejected by default.
3. Error code removals or renames are breaking changes.
4. SDKs should consume helpers through this facade rather than reaching into `chio-core` or `chio-manifest` directly.

## Deferred Work

The following are intentionally deferred until the SDK parity roadmap proves the package-backed remote-edge model:

- `chio-bindings-ffi`
- `chio-bindings-wasm`
- `chio-native`
- Go CGO bridge work
- policy compilation helpers

If any of these become urgent, they should be added only after the team can show the pure TS and pure Python package-backed parity path is working.
