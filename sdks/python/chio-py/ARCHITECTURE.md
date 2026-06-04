# chio-py Architecture Note

## Current Boundaries

- `src/chio/__init__.py` is the public Python SDK facade for hosted sessions,
  auth, receipt queries, nested callback helpers, and errors.
- `src/chio/invariants/` owns low-level cross-language compatibility checks
  for canonical JSON, hashing, signing, capabilities, receipts, and manifests.
- `src/chio/invariants/manifest.py` owns signed manifest parsing, canonical
  signing-body generation, Ed25519 signature verification, and the Python
  `structure_valid` result.
- `tests/test_manifest.py` is the local manifest compatibility harness.

## Pain Points

- Rust `chio-manifest::validate_manifest` rejects blank or whitespace-padded
  manifest identity fields: `server_id`, `name`, and `version`.
- Python currently mirrors tool-name, duplicate-name, input-schema, and
  output-schema checks, but not those top-level identity checks.
- That divergence lets Python callers report `structure_valid: true` for
  manifests that Rust admission and FFI paths reject.

## Security And API Constraints

- Preserve the public `verify_signed_manifest` and
  `verify_signed_manifest_json` return shape.
- Keep canonical JSON byte generation and signature verification independent
  from structural validity.
- Treat identity-field divergence as fail-closed `structure_valid: false`.
- Do not change Rust crates, TypeScript SDK files, or generated artifacts for
  this Python-only parity fix.

## Affected Dependents

- `chio.invariants` consumers get stricter parity with Rust manifest
  admission.
- Existing valid manifests are unchanged.
- Documentation and package exports do not need a signature or API-shape
  change.

## Planned Material Improvement

Add a shared Python manifest text-field validator for `server_id`, `name`, and
`version`, mirroring Rust `validate_manifest_text_field`. Prove the boundary
with tests for blank and padded identity fields while preserving signature and
embedded-key result behavior.

## Manifest Required Permissions Parity Slice

### Current Boundary

- `src/chio/invariants/manifest.py` owns Python signed manifest structure
  admission through the `structure_valid` result.
- Rust `chio-manifest::validate_manifest` rejects malformed
  `required_permissions` after validating manifest identity, tools, and server
  tools.
- `tests/test_manifest.py` is the local SDK harness for this parity boundary.

### Pain Point

Rust rejects blank, whitespace-padded, duplicate, unknown, and non-array
`required_permissions` entries. Python currently accepts those structures after
the identity and tool checks pass, so callers can report `structure_valid: true`
for manifests that Rust admission and FFI paths reject.

### Security And API Constraints

- Preserve the public `verify_signed_manifest` and
  `verify_signed_manifest_json` return shape.
- Keep canonical JSON byte generation and signature verification independent
  from structural validity.
- Treat required-permission divergence as fail-closed `structure_valid: false`.
- Do not change Rust crates, TypeScript SDK files, or generated artifacts for
  this Python parity fix.

### Affected Dependents

- `chio.invariants` consumers get stricter parity with Rust manifest
  admission.
- Existing valid manifests and manifests without `required_permissions` are
  unchanged.
- Documentation and package exports do not need a signature or API-shape
  change.

### Planned Material Improvement

Add Python validation for `required_permissions.read_paths`, `write_paths`,
`network_hosts`, and `environment_variables`: absent or null is accepted,
present values must be arrays of nonblank, unpadded, nonduplicate strings, and
unknown permission fields are rejected.
