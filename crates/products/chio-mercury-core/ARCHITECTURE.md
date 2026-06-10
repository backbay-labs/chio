# chio-mercury-core Architecture

`chio-mercury-core` owns the typed MERCURY evidence contracts layered on Chio
receipt truth. MERCURY is the finance-specific product layer, not a generic
replacement for Chio or Chio-Wall. The crate should keep product evidence
packages verifiable against Chio receipts, checkpoints, bundle manifests, and
publication claims while leaving command orchestration to `chio-mercury`.

## Boundaries

- `receipt_metadata.rs` owns the receipt-embedded MERCURY metadata envelope and
  the workflow, chronology, provenance, disclosure, approval, sensitivity, and
  bundle-reference contracts.
- `bundle.rs` owns bundle manifests, artifact references, canonical manifest
  bytes, and bundle manifest digests.
- `proof_package.rs` owns proof and inquiry packages, Chio evidence export
  verification, checkpoint publication continuity, and rendered-export digest
  binding.
- Lane modules such as `controlled_adoption.rs`, `portfolio_program.rs`,
  `second_portfolio_program.rs`, and `third_program.rs` own bounded product
  package shapes for specific MERCURY motions.
- `fixtures.rs` provides public sample artifacts for CLI and integration tests.
  It must remain obviously valid under the same validators as real packages.

## Validation

- Foundational string validation routes through a shared internal boundary used
  by the metadata, bundle, and proof-package contracts. Optional business
  identifiers on `MercuryWorkflowIdentifiers` (account, desk, strategy, release,
  rollback, exception, inquiry) must be absent or clean, never empty or padded,
  so deserialized evidence cannot carry canonical-byte-relevant whitespace that
  generated builders never emit.
- `lib.rs` is a broad re-export surface, which keeps compatibility but makes
  module-local validation drift harder to see.
- The crate carries a small public smoke test even though proof-package
  validation carries receipt, checkpoint, publication, and rendered-export
  trust semantics.

## Security And API Constraints

- Public structs and schema constants are part of the product evidence contract.
  Preserve public API compatibility unless an incompatible change is explicitly
  justified.
- Validation must fail closed for malformed evidence, schema drift, missing
  metadata, inconsistent workflow scope, invalid checkpoint publication claims,
  and mismatched canonical digests.
- Canonical JSON byte stability and signed Chio receipt compatibility must be
  preserved. Validators can reject malformed deserialized data, but they must
  not mutate canonical package fields silently.
- The CLI crate `chio-mercury` depends on these public builders and fixtures.
  CLI changes should be transitive only when a core boundary change makes them
  necessary.

## Dependents

- `crates/products/chio-mercury` exports and validates MERCURY product packages through
  these contracts.
- Chio evidence export, checkpoint, and receipt crates are upstream inputs to
  proof package verification; their semantics stay in those crates.
- Downstream product docs and generated package files rely on stable schema
  names, field names, and canonical digest behavior.
