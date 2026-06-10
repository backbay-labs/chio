# chio-py Architecture Note

## Boundaries

- `src/chio/__init__.py` is the public Python SDK facade for hosted sessions,
  auth, receipt queries, nested callback helpers, and errors.
- `src/chio/invariants/` owns low-level cross-language compatibility checks
  for canonical JSON, hashing, signing, capabilities, receipts, and manifests.
- `src/chio/invariants/manifest.py` owns signed manifest parsing, canonical
  signing-body generation, Ed25519 signature verification, and the Python
  `structure_valid` result.
- `tests/test_manifest.py` is the local manifest compatibility harness.

## Manifest Structure Admission

`_validate_manifest_structure` mirrors Rust `chio-manifest::validate_manifest`
so a Python caller reports the same `structure_valid` verdict as Rust admission
and FFI paths. The shared rules:

- Identity fields `server_id`, `name`, and `version` must be non-blank and
  unpadded.
- Tool names must be non-blank, unpadded, and unique; `input_schema` and, when
  present, `output_schema` must be JSON objects.
- `required_permissions` is optional. When present, `read_paths`, `write_paths`,
  `network_hosts`, and `environment_variables` must be arrays of non-blank,
  unpadded, non-duplicate strings, and no unknown permission fields are allowed.

## Security And API Constraints

- The public `verify_signed_manifest` and `verify_signed_manifest_json` return
  shape is stable.
- Canonical JSON byte generation and signature verification are independent
  from structural validity.
- Any structural divergence from the Rust rules is fail-closed
  `structure_valid: false`.
