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
  governed continuation wire shapes. Its public API is intentionally split by
  domain:
  - `capability::features`: peer negotiation schema and feature flags.
  - `capability::token`: capability token bodies, signing inputs, token
    signing, validation, and signature verification.
  - `capability::crypto_floor`: capability signature floor policy and
    floor-verification errors.
  - `capability::caveat`: typed caveats and attenuation subset relation rows.
  - `capability::scope`: scopes, grants, operations, constraints, monetary
    amounts, and model metadata.
  - `capability::attenuation`: delegation links, attenuation steps,
    attenuation witnesses, scope hashing, chain validation, and recursive
    delegation minting.
  - `capability::workload_identity`: normalized workload identity parsing and
    validation.
  - `capability::runtime_attestation`: runtime attestation evidence and
    assurance tiers.
  - `capability::trust_policy`: attestation trust policy rules and resolution
    errors.
  - `capability::governance`: governed autonomy, commerce, billing,
    call-chain provenance, continuation tokens, and approval tokens.
- `receipt` owns decision receipts, child request receipts, lineage
  statements, and export envelopes. Its public API is intentionally split by
  signed-artifact responsibility:
  - `receipt::body`: the signed `ChioReceipt` envelope, canonical body, ID
    input, receipt schema constant, receipt ID derivation, and prepared-body
    signing helper.
  - `receipt::signing`: BBS receipt material, signing-body wrapper, nonce
    binding, and BBS binding validation.
  - `receipt::crypto_floor`: receipt signature floor policy and
    floor-verification errors.
  - `receipt::kinds`: receipt kind, boundary, observation, tool-origin,
    redaction, and trust-level enums.
  - `receipt::decision`: authorization decisions and tool-call action hashing.
  - `receipt::metadata`: semantic fields, actor references, guard evidence,
    model metadata, and attribution metadata.
  - `receipt::lineage`: child-request receipts, receipt DAG helpers, lineage
    statements, and signed export envelopes.
  - `receipt::checkpoint`: checkpoint publication and trust-anchor identities.
  - `receipt::economics`: financial, budget, settlement, and economic
    authorization metadata.
  - `receipt::governance`: approval, runtime assurance, commerce, metered
    billing, autonomy, and governed transaction metadata.
  - `receipt::validation`: private shared validators used by receipt modules.
- `manifest` owns the signed tool-server manifest body.
- `session` owns authenticated session anchors, request lineage, and
  normalized session operations. Session roundtrip, signing, schema, and
  URI-normalization tests live in `session/tests.rs` so the wire-type module
  stays focused on production definitions.
- `_generated/chio_wire_v1.rs` is generated code and must not be edited
  directly. It remains a quarantined regeneration artifact, not a public module
  exported from `src/lib.rs`, until generated wire bindings get a deliberate
  no_std-compatible API decision.

## Schema Admission

Every schema-tagged signed artifact rejects unsupported schema IDs before it
verifies signature bytes. A valid signature over an unknown schema is not a
valid current Chio artifact, so schema admission is fail-closed at the owning
wire-type crate rather than deferred to downstream kernels, stores, or
adapters. Session anchors, receipt-lineage statements, and call-chain
continuation tokens enforce this admission check before signing or
verification. Request-lineage records are not signed, but they are
schema-tagged provenance artifacts and expose the same admission check on load
and persistence paths.

The public export surface in `lib.rs` is dense. New helpers stay private unless
they are part of the stable wire API, because widening this crate widens nearly
every downstream crate.

## Security And API Constraints

- Preserve canonical JSON byte stability for every signed payload.
- Preserve existing public structs, field names, serde shapes, and default
  feature behavior.
- Reject unsupported schema identifiers fail-closed.
- Keep validation available in `no_std + alloc`.
- Do not require downstream crates to opt into a public API to retain safety.

## Affected Dependents

`chio-core`, `chio-kernel-core`, `chio-kernel`, `chio-manifest`, adapters,
storage, control-plane crates, bindings, fixtures, and examples all consume
these types. A rejection here surfaces in downstream sign or verify paths, so
tests must cover both the owning crate and any dependent code touched by a
change.
