# chio-go Architecture Note

## Boundaries

- `client/`, `session/`, `transport/`, `auth/`, and `nested/` own the hosted
  SDK runtime surface.
- `invariants/` owns pure-Go compatibility checks for canonical JSON, signing,
  hashing, capabilities, receipts, and manifests.
- `invariants/manifest.go` owns signed manifest parsing, canonical signing-body
  generation, Ed25519 verification, embedded public-key checks, and the Go
  `StructureValid` result.
- `invariants/manifest_test.go` is the local manifest compatibility harness.

## Manifest Structure Admission

`validateManifestStructure` mirrors Rust `chio-manifest::validate_manifest` so a
Go client reports the same `StructureValid` verdict as Rust admission and FFI
paths. The shared rules:

- Identity fields `server_id`, `name`, and `version` must be non-blank and
  unpadded.
- Tool names must be non-blank, unpadded, and unique; `input_schema` and, when
  present, `output_schema` must be JSON objects.
- `required_permissions` is optional. When present, `read_paths`, `write_paths`,
  `network_hosts`, and `environment_variables` must be arrays of non-blank,
  unpadded, non-duplicate strings, and no unknown permission fields are allowed.

## Security And API Constraints

- The public `VerifySignedManifest` and `VerifySignedManifestJSON` return shape
  is stable.
- Canonical JSON byte generation and signature verification are independent
  from structural validity.
- Any structural divergence from the Rust rules is fail-closed
  `StructureValid: false`.
- The parity check requires neither CGO nor native bindings.
