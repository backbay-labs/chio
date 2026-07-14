# chio-attest-buyer architecture

## Overview

`chio-attest-buyer` is a typed trust boundary, not a verifier. It sits between
caller-supplied JSON or structs and two verification backends: `chio-runtime-core`,
which holds the live packet- and review-level admission algorithms, and
`chio-attest-buyer-core`, which holds the offline hardened proof-package
verifier (DSSE, trust bundle, selective disclosure). Callers depend only on
this crate's Chio-owned types and function names; neither backend's shapes
cross the public API.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module declarations and the crate's re-export surface. |
| `src/api.rs` | Every public function: JSON constructors, hashing, verification, report rendering, and proof-replay orchestration. |
| `src/types.rs` | Chio-owned data types (packet, review package/report, lineage, continuation, admission, runtime evidence manifest). |
| `src/schemas.rs` | Schema-id constants, owned locally and never re-exported from `chio-runtime-core`. |
| `src/error.rs` | `BuyerAttestationError` and the `chio_attest_buyer_code` prefix rewrite out of the runtime-core error namespace. |
| `src/validation.rs` | Boundary validation for the `*_from_json` constructors: schema id, non-empty ids, sha256-hex hashes, safe relative paths, duplicate role/path detection. |
| `src/conversions.rs` | Field-by-field mapping between `crate::types` and `chio_runtime_core` equivalents, in both directions. |
| `src/runtime_manifest.rs` | `runtime_evidence_manifest_from_json`, round-tripped through `chio_runtime_core::RuntimeEvidenceManifest` validation. |

## Verification paths

Two independent paths reach the kernel-adjacent verifiers:

1. **Packet and review verification.** `verify_buyer_attestation_packet`,
   `verify_buyer_attestation_review_package`, and
   `verify_buyer_attestation_review_package_with_trust` convert their
   arguments to `chio_runtime_core` shapes (`conversions.rs`), call the
   matching `chio_runtime_core::verify_*` function, convert the report back to
   a Chio type, and rewrite every check and failure code through
   `chio_attest_buyer_code`.
2. **Full proof replay.** `verify_proof_package_json` and
   `verify_buyer_attestation_review_package_with_proof_replay_json` parse a
   proof package, verifier trust bundle, and verification context through
   `chio-attest-buyer-core` (`proof_package`, `trust_bundle`, `context`,
   `report` modules) and take `verify_package_report`'s acceptance verdict.
   The review-package variant runs the trust-context check first; only if it
   accepts does it locate the `proof_package` artifact among the caller's
   `BuyerAttestationReviewSource` bytes, replay it, and append a
   `chio_attest_buyer.review.existing_verifier_replayed` check, flipping
   `accepted` to `false` if the replay rejects.

## Invariants and failure modes

- `*_from_json` constructors never return a Chio struct without passing
  `validation.rs` first: schema id must equal the crate's own constant,
  identifiers must be non-empty, and every `*_sha256` field must be 64 hex
  characters.
- Review package artifacts additionally reject a zero `byte_count`, a
  duplicate `role`, a duplicate `relative_path`, and any path that is
  absolute, contains `\`, `:`, or `//`, or has an empty, `.`, or `..`
  segment.
- Every serde-derived public type uses `#[serde(rename_all = "camelCase",
  deny_unknown_fields)]`: JSON with an unrecognized field or wrong case is
  rejected at parse time, before boundary validation runs.
- Error and check codes never leak `chio_runtime_core`'s internal namespace:
  `chio_attest_buyer_code` rewrites known `chio_buyer*` / `buyer_*` prefixes to
  `chio_attest_buyer.packet.*` / `chio_attest_buyer.review.*` (or the matching
  underscore form) and passes unrecognized codes through unchanged.
  `tests/public_surface.rs` asserts the schema constants are not sourced from
  `chio_runtime_core::CHIO_*_SCHEMA`.
- A buyer packet without a hydrated DSSE envelope stays in an unresolved
  verification state; only the `chio-attest-buyer-core` replay path can move a
  review report from hash-only acceptance to full DSSE-backed acceptance.
- `#![forbid(unsafe_code)]`, `#![forbid(clippy::unwrap_used)]`, and
  `#![forbid(clippy::expect_used)]` at the crate root: every fallible path
  returns `Result`, none panics.

## Dependencies

Internal: `chio-runtime-core` supplies the live packet, review, and
receipt-lineage verification algorithms, canonical artifact hashing
(`buyer_attestation_packet_sha256` and its siblings), and the
`RuntimeEvidenceManifest` validator. `chio-attest-buyer-core` supplies the
offline proof-package, trust-bundle, and verification-context verifier used
for full DSSE replay. Neither is re-exported; both cross the boundary only
inside `api.rs`, `conversions.rs`, and `runtime_manifest.rs`. Dev-only:
`chio-core-types` for test fixtures. External: `serde` and `serde_json` for
the JSON constructors and canonical struct shapes.
