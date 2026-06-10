# chio-ts Architecture Note

## Boundaries

- `src/index.ts` is the public SDK facade. It re-exports client, session, transport, DPoP, receipt query, errors, and invariant helpers.
- `src/invariants/` owns low-level cross-language compatibility checks for canonical JSON, hashing, signing, capabilities, receipts, and manifests.
- `src/invariants/manifest.ts` owns signed manifest parsing, canonical signing-body generation, Ed25519 signature verification, and the TypeScript `structure_valid` result.
- `test/manifest.test.ts` is the local manifest compatibility harness.

## Manifest Structure Admission

`src/invariants/manifest.ts` mirrors Rust `chio-manifest::validate_manifest` so a Node or browser caller reports the same `ManifestVerification.structure_valid` verdict as Rust admission and FFI paths. The shared rules:

- Identity fields `server_id`, `name`, and `version` must be non-blank and unpadded.
- The tool list must be non-empty; tool names must be non-blank, unpadded, and unique; `input_schema` and, when present, `output_schema` must be objects.
- `required_permissions` is optional. When present, `read_paths`, `write_paths`, `network_hosts`, and `environment_variables` must be arrays of non-blank, unpadded, non-duplicate strings, and no unknown permission fields are allowed.

## Security And API Constraints

- The public `verifySignedManifest` and `verifySignedManifestJson` return shape is stable.
- Canonical JSON bytes and signature verification are independent from `structure_valid`; a structural failure does not hide the `signature_valid` result.
- Any structural divergence from the Rust rules is fail-closed `structure_valid: false`.
- `@chio-protocol/sdk/invariants` consumers depend on `ManifestVerification.structure_valid` matching Rust manifest admission. `docs/reference/SDK_TYPESCRIPT_REFERENCE.md` documents the invariants export surface.
