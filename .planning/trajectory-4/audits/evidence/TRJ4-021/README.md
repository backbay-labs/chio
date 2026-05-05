# TRJ4-021 Evidence - chio-tee-frame Signature Validation

## Scope

`chio-tee-frame` now exposes crate-level signed frame validation:

- `signing_payload(frame)` canonicalizes every frame field except
  `tenant_sig`.
- `verify_tenant_sig(frame, tenant_public_key_bytes)` decodes the
  `ed25519:<base64>` signature and verifies it against the canonical payload.
- `validate_signed(frame, tenant_public_key_bytes)` runs structural validation
  first and then verifies the tenant signature.

The existing `validate(frame)` entrypoint remains structural because it has no
tenant key parameter. Callers that possess the tenant public key should use
`validate_signed`.

## Validation

- `cargo test -p chio-tee-frame` passed: 21 unit tests, 2 property tests, 0 doc
  tests.
- `cargo check -p chio-http-core -p chio-tee-frame -p chio-conformance`
  passed.
- `cargo clippy -p chio-http-core -p chio-tee-frame -p chio-conformance --tests -- -D warnings`
  passed.

## Test Coverage

- Valid signed frame accepts.
- Tampered body rejects after the signature is created.
- Wrong tenant key rejects.
