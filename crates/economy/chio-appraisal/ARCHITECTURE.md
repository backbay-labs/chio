# chio-appraisal architecture

## Overview

`chio-appraisal` is a pure evaluation crate: in-memory appraisal, validation,
and cryptographic signing, with no I/O and no runtime state
(`#![forbid(unsafe_code)]`). It projects vendor-specific runtime attestation
evidence into a portable, signed appraisal artifact, evaluates imported
appraisal results against local trust policy without ever widening it, and
prices marketplace guard invocations. `chio-kernel` and the
underwriting/credit/market crates build on its output types; `chio-core`
re-exports it whole as `chio_core::appraisal`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Re-exports `canonical`, `capability`, `crypto`, `error`, `receipt`, `Error`, and `AttestationVerifierFamily` from `chio-core-types`. Declares `appraisal`, `artifact_inventory`, `descriptor`, `types` as private modules flattened via `pub use *`, so only the re-exported names are public, not the module paths. `marketplace_pricing` is `pub mod` with a curated top-level re-export, so both the module path and the flattened names are public. |
| `src/types.rs` | Schema constants and wire types for appraisal artifacts, imported-result evaluation, verifier descriptors, reference-value sets, and trust bundles; the `thiserror` error enums for derivation and verification failures. |
| `src/appraisal.rs` | Per-verifier-family evidence-to-appraisal derivation, `VerifiedRuntimeAttestationRecord` construction against an optional trust policy, and imported-result policy evaluation. |
| `src/artifact_inventory.rs` | Static catalogs: the supported-verifier-family inventory, the normalized-claim vocabulary, and the reason taxonomy. |
| `src/descriptor.rs` | Builds and verifies signed `SignedExportEnvelope` artifacts for verifier descriptors, reference-value sets, and trust bundles. |
| `src/validate.rs` | Private, fail-closed structural validators consumed by `descriptor.rs` (not re-exported). |
| `src/marketplace_pricing.rs` | Deterministic per-invocation marketplace pricing from a base price and tenant reputation tier. |
| `src/tests.rs` | `cfg(test)` unit coverage for the modules above. |

## Appraisal and artifact flows

Evidence to verified record:

1. `derive_runtime_attestation_appraisal` matches `evidence.schema` against
   one of four supported families and normalizes vendor claims into portable
   `RuntimeAttestationNormalizedClaim`s; an unmatched schema fails closed
   with `UnsupportedSchema`.
2. `verify_runtime_attestation_record` wraps the derived appraisal with a
   `RuntimeAttestationPolicyOutcome`. If a local `AttestationTrustPolicy` is
   configured and matches, the record is accepted at the matched rule's
   tier. Otherwise the evidence's own workload-identity binding and
   freshness are checked directly, but the record's effective tier still
   collapses to `None`: the evidence's claimed tier never promotes a record
   on its own.

Imported result evaluation:

- `evaluate_imported_runtime_attestation_appraisal` checks signature,
  schema, result and evidence freshness, exporter policy acceptance,
  issuer/signer/verifier-family allowlists, and required-claim matches,
  collecting a `RuntimeAttestationImportReasonCode` per failure. Any failure
  forces `Reject` with `effective_tier = None`; otherwise the imported tier
  is the minimum of the appraisal's and the exporter's own accepted tier,
  further capped (`Attenuate`) by a configured `maximum_effective_tier`.

Signed export artifacts:

- `descriptor.rs` builds a document, runs it through `validate.rs`, and
  signs it with `SignedExportEnvelope::sign`. Verification re-validates
  shape, checks the `issued_at`/`expires_at` window against `now`, and
  checks the signature. Trust bundles additionally enforce unique
  descriptor and reference-value ids, resolve each reference-value's
  `descriptor_id` and `verifier_family` against a bundled descriptor, and
  allow at most one `Active` reference-value set per `(descriptor_id,
  attestation_schema)`.

Marketplace pricing:

- `compute_checked_marketplace_invocation_price` validates the base price's
  currency and the tenant context's id, then calls the unchecked
  `compute_marketplace_invocation_price`, which applies
  `TIER_DISCOUNT_PER_HUNDRED` with saturating integer arithmetic.

## Invariants and failure modes

- Trust widening requires an explicit local policy match; the evidence's own
  claimed tier never promotes a `VerifiedRuntimeAttestationRecord` by itself.
- Importing with no explicit local policy configured is itself a
  fail-closed rejection reason (`NoLocalPolicy`), not an implicit allow.
- A descriptor's `attestation_schemas` and `signing_key_fingerprints` must be
  non-empty, sorted, and deduplicated, and must reference the crate's
  current canonical appraisal artifact and result schema constants.
- Reference-value-set state fields are mutually exclusive by state: `Active`
  carries neither `superseded_by` nor `revoked_reason`, `Superseded`
  requires a `superseded_by` that is not self-referential, `Revoked`
  requires a non-empty `revoked_reason`.
- Every signed envelope (descriptor, reference-value set, trust bundle) is
  re-validated and signature-checked on verify, never trusted from
  deserialization alone.
- Marketplace pricing is deterministic and integer-only: a zero base price
  stays zero at every tier, and the checked boundary rejects non-uppercase
  or non-three-letter currency codes and empty or whitespace-padded tenant
  ids before a price is computed.

## Dependencies

Internal: `chio-core-types` supplies the types this crate builds on -
`capability::runtime_attestation` (evidence, assurance tiers),
`capability::trust_policy` (`AttestationTrustPolicy`),
`capability::workload_identity`, `crypto` (`Keypair` for signing,
`sha256_hex` for result-id hashing), `receipt::lineage::SignedExportEnvelope`
(the signed-artifact wrapper), and `canonical::canonical_json_bytes`
(result-id derivation). External: `serde`/`serde_json` for wire types,
`thiserror` for the crate's error enums. Dev-only: `chio-test-support`
(`test_expect`/`test_expect_err` helpers).
