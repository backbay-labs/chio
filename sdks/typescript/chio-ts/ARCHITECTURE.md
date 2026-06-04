# chio-ts Architecture Note

## Current Boundaries

- `src/index.ts` is the public SDK facade. It re-exports client, session, transport, DPoP, receipt query, errors, and invariant helpers.
- `src/invariants/` owns low-level cross-language compatibility checks for canonical JSON, hashing, signing, capabilities, receipts, and manifests.
- `src/invariants/manifest.ts` owns signed manifest parsing, canonical signing-body generation, Ed25519 signature verification, and the TypeScript `structure_valid` result.
- `test/manifest.test.ts` is the local manifest compatibility harness.

## Pain Points

- Rust `chio-manifest::validate_manifest` rejects empty or whitespace-padded tool names, duplicate tool names, non-object `input_schema`, and non-object `output_schema`.
- The TypeScript SDK currently mirrors schema, public-key, non-empty tool list, and duplicate-name checks, but not the stricter per-tool name and schema-shape checks.
- That divergence lets browser or Node callers report `structure_valid: true` for malformed signed manifests that Rust admission and FFI paths reject.

## Security And API Constraints

- Preserve the public `verifySignedManifest` and `verifySignedManifestJson` return shape.
- Preserve signature verification behavior. Structural failure must not hide the independent `signature_valid` result.
- Keep canonical JSON byte generation untouched.
- Treat malformed tool metadata as fail-closed `structure_valid: false`.

## Affected Dependents

- `@chio-protocol/sdk/invariants` consumers depend on `ManifestVerification.structure_valid` matching Rust manifest admission.
- `docs/reference/SDK_TYPESCRIPT_REFERENCE.md` documents the invariants export surface but does not need a signature or API-shape change.
- No Rust crate should change for this SDK parity fix.

## Planned Material Improvement

Mirror Rust manifest structure checks in `src/invariants/manifest.ts`: reject empty or whitespace-padded tool names, reject non-object `input_schema`, and reject non-object `output_schema` when present. Prove with red TypeScript manifest tests before changing the validator.

## Manifest Identity Parity Slice

### Current Boundary

- `src/invariants/manifest.ts` owns TypeScript signed manifest structure
  admission through `ManifestVerification.structure_valid`.
- Rust `chio-manifest::validate_manifest` owns the canonical admission rule
  for signed manifests before verification and persistence.
- `test/manifest.test.ts` is the local SDK harness for this parity boundary.

### Pain Point

Rust now rejects blank or whitespace-padded manifest identity fields:
`server_id`, `name`, and `version`. The TypeScript SDK currently validates the
schema, non-empty tool list, tool names, duplicate tools, and schema shapes,
but it does not reject malformed top-level identity fields. That lets Node or
browser callers accept manifest structures that Rust rejects.

### Security And API Constraints

- Preserve the public `verifySignedManifest` and `verifySignedManifestJson`
  return shape.
- Keep canonical JSON bytes and signature verification independent from
  `structure_valid`.
- Treat identity-field divergence as fail-closed `structure_valid: false`.
- Do not change Rust crates or generated artifacts for this SDK-only parity
  fix.

### Affected Dependents

- `@chio-protocol/sdk/invariants` consumers get stricter structure parity with
  Rust manifest admission.
- Existing valid manifests are unchanged.
- Documentation and package exports do not need a signature or API-shape
  change.

### Planned Material Improvement

Add a shared TypeScript manifest text-field validator for `server_id`, `name`,
and `version`, mirroring Rust `validate_manifest_text_field`. Prove the
boundary with tests for blank and padded identity fields while preserving
signature and embedded-key result behavior.

## Manifest Required Permissions Parity Slice

### Current Boundary

- `src/invariants/manifest.ts` owns TypeScript signed manifest structure
  admission through `ManifestVerification.structure_valid`.
- Rust `chio-manifest::validate_manifest` rejects malformed
  `required_permissions` after validating manifest identity, tools, and server
  tools.
- `test/manifest.test.ts` is the local SDK harness for this parity boundary.

### Pain Point

Rust rejects blank, whitespace-padded, duplicate, unknown, and non-array
`required_permissions` entries. The TypeScript SDK currently accepts those
structures after the identity and tool checks pass, so Node or browser callers
can report `structure_valid: true` for manifests Rust rejects.

### Security And API Constraints

- Preserve the public `verifySignedManifest` and `verifySignedManifestJson`
  return shape.
- Keep canonical JSON bytes and signature verification independent from
  `structure_valid`.
- Treat required-permission divergence as fail-closed `structure_valid: false`.
- Do not change Rust crates or generated artifacts for this SDK-only parity fix.

### Affected Dependents

- `@chio-protocol/sdk/invariants` consumers get stricter structure parity with
  Rust manifest admission.
- Existing valid manifests and manifests without `required_permissions` are
  unchanged.
- Documentation and package exports do not need a signature or API-shape change.

### Planned Material Improvement

Add TypeScript validation for `required_permissions.read_paths`,
`write_paths`, `network_hosts`, and `environment_variables`: absent or null is
accepted, present values must be arrays of nonblank, unpadded, nonduplicate
strings, and unknown permission fields are rejected.
