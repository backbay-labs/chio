# chio-manifest architecture

## Overview

`chio-manifest` defines `chio.manifest.v1`, the signed discovery-and-trust
artifact a Chio tool server uses to declare its tools before the kernel admits
it. The crate is pure data, validation, and signing: no I/O, no runtime state,
`#![forbid(unsafe_code)]`. Structural validation (`validate_manifest`) is
deliberately independent of signer material, so a manifest's shape can be
checked before a keypair is available; `sign_manifest` and `verify_manifest`
layer the Ed25519 trust check on top. Tool-definition synthesis from a wire
protocol, kernel admission state, capability issuance, and guard execution are
deliberately absent from this crate; they live in the protocol adapters,
`chio-kernel`, and the guard crates.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Manifest schema types (`ToolManifest`, `ToolDefinition`, `ToolPricing`, `PricingModel`, `RequiredPermissions`, `LatencyHint`, `ServerTool`, `SignedManifest`, `ManifestError`) and `sign_manifest`/`verify_manifest`. |
| `src/validation.rs` | Structural validation (`validate_manifest` and its field-level helpers). Private module; only `validate_manifest` is re-exported. |

## Signing and verification lifecycle

1. A tool server (typically a protocol adapter, e.g. `chio-mcp-adapter`) builds
   a `ToolManifest` literal from its `ToolDefinition`s and embeds its own
   Ed25519 public key as hex in `public_key`.
2. `sign_manifest` calls `validate_manifest`, then confirms `public_key`
   hex-decodes and equals the signing `Keypair`'s public key
   (`ensure_embedded_public_key_matches`), then signs the canonical JSON
   encoding of the manifest and returns `SignedManifest { manifest, signature,
   signer_key }`.
3. `verify_manifest` re-runs `validate_manifest` and the embedded-key check,
   confirms `signed.signer_key` equals the caller-supplied trusted `PublicKey`,
   and cryptographically verifies `signature` over the manifest's canonical
   JSON.
4. A failure at any step returns a `ManifestError`; there is no partial-success
   result.

## Invariants and failure modes

- `schema` must equal `TOOL_MANIFEST_SCHEMA` (`"chio.manifest.v1"`); any other
  value is `UnsupportedSchema`.
- `validate_manifest` never inspects `public_key` material; it is a pure
  structural gate usable before a signer exists.
- `tools` must be non-empty with unique names (`EmptyManifest`,
  `DuplicateToolName`); `server_tools` entries must be unique
  (`DuplicateServerTool`).
- `input_schema` must be a JSON object; `output_schema`, if present, must also
  be a JSON object (`InvalidInputSchema`, `InvalidOutputSchema`).
- `server_id`, `name`, `version`, tool names, and required-permission entries
  must be non-empty, unpadded, and free of control characters
  (`InvalidManifestField`, `InvalidToolName`, `InvalidRequiredPermission`);
  permission entries must also be unique within their list
  (`DuplicateRequiredPermission`).
- Pricing validates per model: `Flat` requires `base_price`;
  `PerInvocation`/`PerUnit` require `unit_price` and `billing_unit`; `Hybrid`
  requires both prices and `billing_unit`. Any price present must carry a
  currency of exactly 3 uppercase ASCII letters (ISO 4217 shape; not checked
  against the real currency list).
- `ToolManifest`, `ToolDefinition`, `ToolPricing`, `RequiredPermissions`, and
  `SignedManifest` are all annotated `#[serde(deny_unknown_fields)]`;
  unrecognized JSON fields fail to deserialize instead of being dropped.
- `sign_manifest` and `verify_manifest` fail closed with `VerificationFailed`
  on an unparseable or mismatched embedded `public_key`, a signer-key
  mismatch, or an invalid signature.

## Dependencies

- `chio-core` - `Keypair`, `PublicKey`, `Signature` (Ed25519 signing and
  canonical-JSON verification, including the FIPS/hybrid-capable
  `PublicKey::from_hex` decoder) and `MonetaryAmount` (also used for
  capability budget scoping in `chio-core-types::capability::scope`).
- `serde`, `serde_json` - manifest (de)serialization and JSON Schema values.
- `thiserror` - `ManifestError`.
