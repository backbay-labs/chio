# chio-core-types Architecture Note

## Module Boundaries

`chio-core-types` owns the portable protocol substrate. It must remain
`no_std + alloc` under `--no-default-features`, and it must not depend on
policy, kernel, storage, adapter, or product crates.

- `canonical` owns RFC 8785 canonical JSON bytes and the typed
  `CanonicalBytes` witness used by signing and hashing callers.
- `crypto`, `hashing`, and `merkle` own portable primitive wrappers and
  algorithm-tagged signatures.
- `capability` owns capability, delegation, attenuation, approval, and
  governed continuation wire shapes.
- `receipt` owns decision receipts, child request receipts, lineage
  statements, and export envelopes.
- `manifest` owns the signed tool-server manifest body.
- `session` owns authenticated session anchors, request lineage, and
  normalized session operations.
- `_generated/chio_wire_v1.rs` is generated code and must not be edited
  directly.

## Pain Points

The crate is intentionally broad because it is the stable wire substrate, but
that breadth makes signed-artifact invariants easy to implement unevenly.
Capability tokens already reject unsupported schema IDs before verification,
while other schema-tagged signed artifacts have historically verified only the
signature bytes. That is too weak for the protocol contract: a valid signature
over an unknown schema is still not a valid current Chio artifact.

The public export surface in `lib.rs` is also dense. New helpers should stay
private unless they are part of the stable wire API, because widening this crate
widens nearly every downstream crate.

## Security And API Constraints

- Preserve canonical JSON byte stability for every signed payload.
- Preserve existing public structs, field names, serde shapes, and default
  feature behavior.
- Reject unsupported schema identifiers fail-closed.
- Keep all new validation available in `no_std + alloc`.
- Do not require downstream crates to opt into a new public API to retain
  current safety.

## Affected Dependents

`chio-core`, `chio-kernel-core`, `chio-kernel`, `chio-manifest`, adapters,
storage, control-plane crates, bindings, fixtures, and examples all consume
these types. Any rejection added here can surface in downstream sign or verify
paths, so tests must cover both the owning crate and any dependent code touched
by the change.

## Planned Improvement

Complete the schema-tagged artifact boundary in this crate by rejecting
unsupported schema IDs for session anchors, receipt-lineage statements, and
call-chain continuation tokens before signing or verification. Request-lineage
records are not signed, but they are still schema-tagged provenance artifacts,
so the owning type must expose the same fail-closed schema admission check for
load and persistence paths. This is an architectural invariant, not a cosmetic
cleanup: it centralizes current-schema admission at the owning wire-type crate
and prevents downstream kernels, stores, or adapters from treating future or
foreign schema payloads as valid merely because their bytes deserialize.
