# chio-go Architecture Note

## Current Boundaries

- `client/`, `session/`, `transport/`, `auth/`, and `nested/` own the hosted
  SDK runtime surface.
- `invariants/` owns pure-Go compatibility checks for canonical JSON, signing,
  hashing, capabilities, receipts, and manifests.
- `invariants/manifest.go` owns signed manifest parsing, canonical signing-body
  generation, Ed25519 verification, embedded public-key checks, and the Go
  `StructureValid` result.
- `invariants/manifest_test.go` is the local manifest compatibility harness.

## Pain Points

- Rust `chio-manifest::validate_manifest` rejects blank or whitespace-padded
  top-level manifest identity fields: `server_id`, `name`, and `version`.
- Go already rejects empty or padded tool names, duplicate tool names, and
  non-object schemas, but it does not reject malformed top-level identity
  fields.
- That divergence lets Go clients report `StructureValid: true` for artifacts
  that Rust admission and FFI paths reject.

## Security And API Constraints

- Preserve the public `VerifySignedManifest` and `VerifySignedManifestJSON`
  return shape.
- Keep canonical JSON byte generation and signature verification independent
  from structural validity.
- Treat identity-field divergence as fail-closed `StructureValid: false`.
- Do not require CGO or native bindings for this parity check.

## Planned Material Improvement

Add a shared Go manifest text-field validator for `server_id`, `name`, and
`version`, mirroring the Rust manifest identity boundary and the existing tool
name rule. Prove the boundary with tests for blank and padded identity fields
while preserving signature and embedded-key result behavior.

## Manifest Required Permissions Parity Slice

### Current Boundary

- `invariants/manifest.go` owns signed manifest structure admission through the
  `StructureValid` result.
- Rust `chio-manifest::validate_manifest` rejects malformed
  `required_permissions` after validating manifest identity, tools, and server
  tools.
- `invariants/manifest_test.go` is the local manifest compatibility harness.

### Pain Point

Rust rejects blank, whitespace-padded, duplicate, unknown, and non-array
`required_permissions` entries. Go currently accepts those structures after the
identity and tool checks pass, so clients can report `StructureValid: true` for
artifacts that Rust admission and FFI paths reject.

### Security And API Constraints

- Preserve the public `VerifySignedManifest` and `VerifySignedManifestJSON`
  return shape.
- Keep canonical JSON byte generation and signature verification independent
  from structural validity.
- Treat required-permission divergence as fail-closed `StructureValid: false`.
- Do not require CGO or native bindings for this parity check.

### Affected Dependents

- Pure-Go invariant consumers get stricter parity with Rust manifest admission.
- Existing valid manifests and manifests without `required_permissions` are
  unchanged.
- Package exports do not need a signature or API-shape change.

### Planned Material Improvement

Add Go validation for `required_permissions.read_paths`, `write_paths`,
`network_hosts`, and `environment_variables`: absent or nil is accepted,
present values must be arrays of nonblank, unpadded, nonduplicate strings, and
unknown permission fields are rejected.
