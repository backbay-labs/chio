# chio-runtime-proof-parity architecture

## Overview

`chio-runtime-proof-parity` is a pure data-validation crate: parsing
caller-supplied JSON bytes is its only I/O, it holds no runtime state, and it
forbids unsafe code. It lives in `crates/kernel` as a shared contract between
`chio-runtime-core` and `chio-proof-room` rather than inside either, so both
can check the same report and artifact-bundle shapes against one fail-closed
implementation. It does not regenerate proofs, read evidence stores, or run
workflows; it only defines and checks the shapes of artifacts that describe
those processes.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Schema constants; `RuntimeProofParityReport`, `RuntimeProofParityMismatch`, and `RuntimeProofRegenerationArtifacts` types; `RuntimeProofParityError`; `validate_runtime_proof_parity_report` and `validate_runtime_proof_regeneration_artifacts` plus their private schema/hash/run-id helpers. |

## Validation flow

`validate_runtime_proof_parity_report`:

1. Check `schema` equals `CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA`.
2. Check the four package/report sha256 fields are 64 lowercase hex characters.
3. Check `accepted` and `failure_code` are consistent in both directions
   (accepted cannot carry a code, rejected must carry one).
4. Check `compared_fields` is non-empty.
5. If `accepted`, check `mismatches` is empty and the static/runtime package
   hashes and static/runtime verifier-report hashes are pairwise equal.
6. Check every `RuntimeProofParityMismatch` has a non-empty `field` and valid
   sha256 hashes.

`validate_runtime_proof_regeneration_artifacts` (all seven artifacts arrive as
raw `&[u8]`):

1. Parse the four JSON-typed artifacts (proof regeneration report and input,
   evidence manifest, workflow run report) and check each against its schema
   constant.
2. Check all four share one `runId` (the report is the anchor; input,
   manifest, and workflow report must match it).
3. Check the proof regeneration report and the workflow run report are each
   `accepted` with no `failureCode`; reject if either is not accepted.
4. Canonically hash (RFC 8785 JSON, sha256) the report, manifest, and
   workflow report values parsed in step 1, then parse and canonically hash
   the proof package, verifier report, and workflow receipt bytes the same
   way.
5. Check the cross-artifact hash fields agree with those canonical hashes:
   the workflow report and manifest both bind the proof report's hash; the
   manifest and input both bind the workflow report's hash; the input binds
   the manifest's hash; the proof report itself binds the proof package,
   verifier report, and workflow receipt hashes.
6. Check `sourceRecords` on the input and the report are identical, then bind
   each source record's `stepIndex` to the workflow report's matching
   `stepEvidence` entry and check the four evidence-hash fields
   (`admissionReportSha256`, `toolReceiptSha256`, `bilateralDsseSha256`,
   `workflowStepSha256`) are present, non-empty, and equal on both sides.
7. Check every byte-bearing artifact (proof package, verifier report,
   workflow receipt, and the raw proof-regeneration-report and
   workflow-run-report bytes) against its `entries[]` record in the evidence
   manifest, this time by raw-byte sha256 and byte count rather than
   canonical hash.

## Invariants and failure modes

- Every check fails closed: unsupported schema, malformed or wrong-case
  sha256 hex, missing required fields, mismatched run IDs, hash drift, and
  unbound step evidence all produce a `RuntimeProofParityError::Rejected`
  with a stable `code`.
- `RuntimeProofParityReport` validation is fail-closed both ways: `accepted`
  reports cannot carry mismatches or hash drift, and non-accepted reports
  must carry a `failure_code`.
- Regeneration bundle validation only requires the proof regeneration report
  and workflow run report to be `accepted` with no `failureCode`; anything
  else is rejected before any hash binding is checked.
- Source-record and workflow-step evidence-hash fields must be present and
  non-empty on both sides; a missing or blank field is rejected rather than
  treated as a skippable non-match.
- Cross-artifact binding hashes are RFC 8785 canonical-JSON sha256 of each
  artifact's parsed value; evidence-manifest entries instead check raw-byte
  sha256 and byte count of the exact bytes the caller supplied.

## Dependencies

`chio-core-types` supplies `crypto::canonical_json_bytes` (RFC 8785 canonical
JSON) and `crypto::sha256_hex`, the hashing primitives every check is built
on. `serde` and `serde_json` (de)serialize the typed parity report and parse
the untyped regeneration artifacts as `serde_json::Value`. `thiserror`
derives `RuntimeProofParityError`.
