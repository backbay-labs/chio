# chio-core Architecture

## Role

`chio-core` is the unified protocol import surface for consumers that want one
crate rather than direct imports from every domain crate. It re-exports
`chio-core-types` for canonical protocol artifacts and re-exports the dedicated
domain crates for appraisal, autonomy, credit, federation, governance, markets,
underwriting, and Web3 contracts.

The crate also owns the Chio extension standards that do not naturally belong to
one lower-level protocol crate:

- `extension.rs` defines the extension inventory, official stack package,
  extension manifest, negotiation report, and qualification matrix.
- `identity_network.rs` defines cross-network identity and trust artifacts.
- `standards.rs` defines shared machine-readable standard catalogs.
- `lib.rs` is a compatibility facade and should stay additive unless a
  deliberate breaking release is approved.

## Boundaries

`chio-core` must stay pure protocol logic. It should not perform I/O, launch
runtimes, read policy files, or depend on kernel state. Validation functions can
compare in-memory artifacts and must fail closed on malformed schemas, missing
fields, duplicate identifiers, unknown references, privilege widening, truth
mutation, and extension evidence modes that lack local policy activation.

Public re-exports are a compatibility contract. New helpers should be additive,
and existing exported names should not be removed or narrowed without an
explicit migration.

## Current Pain Points

The extension contract is intentionally cross-artifact: inventories name
extension points, official stack packages name first-party components, manifests
target those components, and qualification matrices record the cases that prove
the boundary. The most fragile code is therefore not field validation, but
agreement between artifacts.

One concrete gap is bidirectional official stack consistency. A package
component can name its extension points, and an inventory point can name its
official components. Both sides need to agree. If either side claims an
official point-to-component edge that the other side does not reciprocate,
negotiation can treat a manifest as targeting an official baseline that the
inventory and stack do not actually share.

## Local Invariants For This Slice

- `validate_extension_inventory` validates the inventory in isolation.
- `validate_official_stack_package` validates the inventory and package
  together, including bidirectional point-to-component agreement before profile
  coverage is trusted.
- `validate_extension_manifest` validates manifest shape and runtime guardrails
  independent of a package.
- `negotiate_extension` assumes the three artifact validators have already
  rejected malformed inputs, then reports compatibility reasons for valid but
  incompatible artifacts.
- `validate_qualification_matrix` remains shape-only until a separate
  contextual matrix validator is added.

## Verification Focus

Tests should cover facade export stability, extension inventory/package graph
agreement in both directions, manifest negotiation rejection paths, identity
network validation, and byte-stable serde for public protocol artifacts that
flow through this facade. When lower-level crates add signed or canonical
types, `chio-core` verification should prove the re-export path does not
change their construction, validation, or serialized field names.

## Improvement In This Slice

Strengthen `validate_official_stack_package` so the inventory and official
stack form one authoritative graph for official components. Inventory-to-stack
and stack-to-inventory mismatches must fail closed before negotiation evaluates
profiles, supported components, or runtime guardrails.
