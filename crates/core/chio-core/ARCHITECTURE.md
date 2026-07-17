# chio-core architecture

## Overview

`chio-core` sits at the base of the dependency graph as a pure protocol crate:
in-memory types, validation, and cryptography with no I/O and no runtime state.
It plays two roles. It is a facade that re-exports `chio-core-types` and the
economic and trust domain crates under one `chio_core::*` path, and it owns three
cross-cutting contracts (`extension`, `identity_network`, `standards`) that
constrain how the protocol is extended without belonging to any single
lower-level crate.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Facade. Re-exports `chio-core-types` modules and the domain crates, and declares the three owned modules. Additive compatibility surface. |
| `src/extension/model.rs` | Data models: extension inventory, official-stack package, extension manifest, negotiation report, qualification matrix. |
| `src/extension/validation.rs` | Fail-closed shape, reference, guardrail, and qualification validation. |
| `src/extension/negotiation.rs` | Compatibility negotiation and rejection-report construction. |
| `src/extension/error.rs` | `ExtensionContractError` reporting. |
| `src/identity_network/types.rs` | Public identity profile, wallet directory entry, and routing manifest artifacts. |
| `src/identity_network/validation.rs` | Entry-point validators for identity and wallet artifacts. |
| `src/identity_network/validators.rs` | Shared field-level checks used by the validators. |
| `src/standards.rs` | Portable claim catalog, portable identity binding, governed-auth binding, and provenance-anchor constants. |

## Boundaries

`chio-core` performs no I/O, launches no runtime, reads no policy files, and
holds no kernel state. Validation compares in-memory artifacts only. The public
re-export set is a compatibility contract: exported names are additive, and
removing or narrowing one is a breaking change that requires a deliberate
migration.

## Invariants and failure modes

- Every validator fails closed on malformed schema, missing fields, duplicate
  identifiers, unknown references, privilege widening, truth mutation, and
  extension evidence modes without local policy activation.
- Official-stack agreement is bidirectional. A package component names its
  extension points and an inventory point names its official components; if
  either side asserts a point-to-component edge the other does not reciprocate,
  validation rejects before negotiation.
- `negotiate_extension` assumes the three artifact validators have already run.
  It reports compatibility for valid-but-incompatible artifacts and does not
  re-check shape.
- `validate_qualification_matrix` is shape-only; contextual matrix validation is
  not wired.

## Dependencies

Internal: `chio-core-types` holds the actual protocol definitions; the domain
crates `chio-appraisal`, `chio-autonomy`, `chio-credit`, `chio-federation`,
`chio-governance`, `chio-listing`, `chio-market`, `chio-open-market`,
`chio-underwriting`, and `chio-web3` supply the economic and trust artifacts this
crate re-exports. External: `serde`/`serde_json` for artifacts, `ed25519-dalek`,
`sha2`, `hex` for signing and hashing, and `url` for identity references.
