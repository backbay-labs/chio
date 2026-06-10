# chio-manifest Architecture Notes

## Boundary

`chio-manifest` owns the native Chio tool discovery artifact:
`chio.manifest.v1`. It defines the manifest schema structs, validates
manifest-level invariants, signs manifests over canonical JSON, and verifies
signed manifests against Chio public keys. It should not own adapter-specific
tool synthesis, kernel admission state, capability issuance, guard execution,
or billing enforcement.

## Pricing Metadata

The manifest carries advisory pricing metadata that operators and authorities
can use before issuing budgeted capabilities. `validate_manifest` rejects
malformed identity, schema, server-tool, sandbox-permission, and pricing
metadata before a manifest is signed. Flat pricing requires a base price;
per-invocation and per-unit pricing require a unit price plus billing unit;
hybrid pricing requires both base and unit prices plus a billing unit. Any
present price amount must carry a three-letter uppercase currency code, and
billing units must be non-empty and unpadded. The kernel enforces issued
capability budgets; the signed discovery artifact must not carry ambiguous
quote inputs that mislead authority-side planning.

## Security And API Constraints

- `chio.manifest.v1` must stay frozen and backward-compatible for valid
  manifests.
- Unknown schema values, duplicate tool names, malformed server-tool
  allowlists, and non-object per-tool schemas must fail closed in structural
  validation.
- Missing, malformed, or mismatched signer material must fail closed in
  `sign_manifest` and `verify_manifest`, not in unsigned structural validation.
- Validation must use Chio's algorithm-aware `PublicKey` decoder so Ed25519 and
  supported FIPS encodings stay compatible when signed material is evaluated.
- Server identity, display name, version, and required permission entries are
  adapter and kernel admission metadata. Empty, padded, or duplicate text values
  should fail closed during structural validation.
- Pricing metadata is advisory, not the enforcement boundary, but signed
  manifests must still reject model shapes that omit required quote fields.
- Existing valid native builder output for flat, per-invocation, per-unit, and
  hybrid pricing must continue to validate.
- Adapter fixture updates should not be required solely to satisfy unsigned
  structural validation. Fixtures that exercise signed-manifest admission should
  still use deterministic valid keys.

## Affected Dependents

Dependents are adapter tests and examples that synthesize manifests before
calling `validate_manifest`. Structural validation rejects malformed tool
schemas for those dependents, while unsigned manifests with placeholder public
keys remain usable until a caller explicitly signs or verifies the manifest.
`NativeTool` pricing builders emit the required fields.
