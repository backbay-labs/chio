# chio-disclosure-lineage architecture

## Overview

`chio-disclosure-lineage` is a pure verification library: no I/O, no runtime
state, invoked synchronously by a caller holding a `DisclosureLineageBundle`
and a set of trusted signer keys supplied per call through
`DisclosureLineageVerifierTrust`. It holds no keys and no kernel state of its
own, and it is not part of any async runtime.

A selective disclosure is accepted only when five artifacts agree: a capsule
declaring what was disclosed and hidden, a signed lineage subgraph proving
graph-bound receipt evidence backs it, a leakage ledger accounting for every
unit of disclosed information and its score, a privacy profile stating what
the verifier permits, and a crypto context report attesting the underlying
cryptographic proof was checked. The crate cross-validates and binds these
five artifacts; it does not produce any of them, evaluate cryptographic key
or revocation state, or generate BBS proofs (`chio-selective-disclosure` owns
all three).

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Re-exports the public types and verifier functions. No logic. |
| `src/types.rs` | Serde data model for all five artifact kinds, their schema-tag constants, and `DisclosureLineageError`. Every struct carries `#[serde(deny_unknown_fields)]`. |
| `src/verifier.rs` | Digesting, Ed25519 signing/verification, per-artifact validators, cross-artifact binding checks, and the fixed hidden-predicate catalog. |

## Verification pipeline

`verify_disclosure_lineage_bundle_with_trust` runs eight steps in order and
returns on the first error:

1. `validate_capsule` - schema tag, non-empty refs, unique disclosed fields
   and hidden-predicate ids.
2. `validate_privacy_profile` - schema tag, non-empty core fields, uniqueness
   of the allow/forbid lists, at least one sensitivity class.
3. `validate_lineage` (with trust) - schema tag; sha256-shape digests; node
   kind, evidence-class, and derived-hash checks; root-receipt shape; edge
   shape and kind/relation restriction; graph closure
   (`validate_lineage_closure`); redaction consistency
   (`validate_lineage_redactions`); recomputes the frontier,
   checkpoint-inclusion, and subgraph digests and compares them to the
   declared values; verifies the Ed25519 signature against
   `trusted_lineage_signer_keys`.
4. `validate_leakage_ledger` (against the profile) - schema tag,
   ledger-to-profile identity (`policy_profile_id`, `privacy_profile_ref`,
   `audience`), `accepted == true`, per-entry checks (sensitivity-class
   membership, residual-inference-note requirement for sensitive entries,
   uniqueness), and a recomputed total score within the profile's maximum.
5. `validate_bundle_bindings` - cross-artifact ref identity across capsule,
   lineage, leakage ledger, and privacy profile; requires
   `crypto_context_report` to be present and checks its schema, refs,
   verdict, claim whitelist, and disclosed-field-set equality with the
   capsule (signature not yet checked here).
6. `validate_privacy_profile_policy` - capsule leakage budget against the
   profile; disclosed fields checked for sensitivity classification and
   allow/forbid membership; hidden predicates matched against
   `SUPPORTED_HIDDEN_PREDICATES` and checked for allow/forbid membership.
7. `validate_leakage_coverage` - every disclosed field and hidden predicate
   has a matching, policy-allowed leakage-ledger entry; if the capsule
   discloses anything, all `REQUIRED_DISCLOSURE_DERIVED_FACTS` must also be
   present.
8. `verify_crypto_context_report_signature_with_trust` - Ed25519 check
   against `trusted_crypto_context_report_signer_keys`; the report's
   `verified_claims` are appended to the result.

The returned `DisclosureLineageVerifierReport` carries the union of claims
proven by the lineage subgraph, the leakage ledger, and the crypto context
report.

## Invariants and failure modes

- Every validator fails closed: the first mismatch returns
  `DisclosureLineageError::InvalidArtifact` and no partial report is built.
- Layered digest binding: a node's `artifact_sha256` and `source_id_hash`
  must equal `sha256(receipt_ref)`; the frontier digest hashes the sorted
  `id:artifact_sha256:depth` triples of nodes that are never an edge's `from`
  (leaf nodes); the checkpoint-inclusion digest is
  `sha256(checkpoint_ref|frontier_sha256)`; the subgraph digest is the
  canonical-JSON hash of the subgraph excluding `schema`, `subgraph_sha256`,
  and `signature`.
- The two signed artifacts use different signature schemes: a lineage
  subgraph signs the hex digest string's bytes (`Keypair::sign`); a crypto
  context report signs the artifact canonically with its own `signature`
  field cleared first (`Keypair::sign_canonical`). Both produce the same
  `sig-ed25519:<pubkey-hex>:<signature-hex>` wire format.
- Trust is two independent key sets held in `DisclosureLineageVerifierTrust`:
  a lineage signer is never accepted as a crypto-context-report signer
  unless the caller adds the same key to both sets.
- Evidence-class floor: every lineage node's rank (`asserted` < `observed` <
  `verified`/`derived`, the latter two tied) must be at least the subgraph's
  declared `required_evidence_class` rank.
- Hidden predicates are restricted to the `SUPPORTED_HIDDEN_PREDICATES` allowlist,
  which currently holds one entry (`amount_lte_100`); every field of a capsule's
  predicate must match that entry exactly and its `result` must be `true`.
- `crypto_context_report` is `Option` on the wire (omittable in JSON) but
  mandatory for verification: `validate_bundle_bindings` rejects `None`.
- The privacy profile's cryptographic policy fields
  (`required_key_epoch_min`, `forbidden_key_epochs`,
  `required_status_freshness_seconds`, `required_transparency_state`,
  `max_presentation_age_seconds`, `required_holder_binding`) are carried and
  shape-checked but never evaluated in this crate.
  `chio-selective-disclosure::crypto_context::policy` evaluates them against
  a `CryptoVerificationContext` before producing the signed report this
  crate verifies.

## Dependencies

- `chio-core-types` - canonical JSON (`canonical_json_bytes`), sha256 hashing
  (`sha256_hex`), and the Ed25519 `Keypair`/`PublicKey`/`Signature` types
  used for every digest and signature in the crate. Imported under its own
  name; no `package = ` aliasing.
- `serde` (`derive`) - (de)serializes every artifact type.
- `thiserror` - derives `DisclosureLineageError`.
