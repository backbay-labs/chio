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

## Pain Points

- Foundational string validation is duplicated across modules. Some paths reject
  padded identifiers while others only reject empty values, so deserialized
  evidence can carry canonical-byte-relevant whitespace that generated builders
  would never emit.
- `lib.rs` is a broad re-export surface. That is acceptable for compatibility,
  but it makes module-local validation drift harder to see.
- The crate has only a small public smoke test even though proof-package
  validation carries receipt, checkpoint, publication, and rendered-export
  trust semantics.
- There is no dedicated MERCURY README in the crate. Product context is
  currently inferred from `docs/operations/STRATEGIC_ROADMAP.md` and the
  Chio-Wall boundary docs.

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

## Affected Dependents

- `crates/chio-mercury` exports and validates MERCURY product packages through
  these contracts.
- Chio evidence export, checkpoint, and receipt crates are upstream inputs to
  proof package verification, but this slice should not move their semantics.
- Downstream product docs and generated package files rely on stable schema
  names, field names, and canonical digest behavior.

## Planned Improvement

Introduce a small internal validation boundary for foundational MERCURY string
fields and use it in the metadata, bundle, and proof-package contracts. The
current slice hardens `MercuryWorkflowIdentifiers`: optional business
identifiers such as account, desk, strategy, release, rollback, exception, and
inquiry IDs must be absent or clean, never present as empty or padded strings.
Builders already emit clean values, so accepting padded deserialized identifiers
only weakens verification and creates divergent canonical bytes.
