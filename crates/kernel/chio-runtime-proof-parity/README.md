# chio-runtime-proof-parity

Schema and fail-closed validation for runtime proof parity: comparing a
statically generated proof package against one regenerated from runtime
evidence. The crate defines the wire shape of parity reports and
proof-regeneration artifact bundles and validates both; it does not generate,
store, or serve proofs itself.

## Responsibilities

- Define `RuntimeProofParityReport` and `RuntimeProofParityMismatch`, the wire
  shape for comparing a static proof package against a runtime-regenerated one.
- Validate parity reports fail-closed: schema, sha256 hex shape on all four
  package/report hashes, `accepted`/`failure_code` consistency, non-empty
  `compared_fields`, and (when accepted) zero mismatches plus hash equality
  between the static and runtime package and verifier-report hashes.
- Define `RuntimeProofRegenerationArtifacts`, a borrowed bundle of the seven
  raw JSON artifacts a runtime proof-regeneration run produces.
- Validate a regeneration bundle fail-closed: schema and a shared `runId`
  across the four JSON-typed artifacts, `accepted` with no `failureCode` on
  the proof regeneration and workflow run reports, canonical-hash binding
  across the report/input/manifest/workflow-report chain, per-step
  evidence-hash binding between source records and workflow step evidence,
  and raw-byte sha256/byte-count binding against the evidence manifest's
  entries.
- Report every rejection through `RuntimeProofParityError::Rejected`, a
  stable `code` plus a human-readable `detail`.

## Public API

- `RuntimeProofParityReport`, `RuntimeProofParityMismatch` - the parity-report
  wire shape (serde `camelCase`, `deny_unknown_fields`).
- `RuntimeProofRegenerationArtifacts<'a>` - borrowed bundle of the seven raw
  JSON artifacts (proof regeneration report and input, evidence manifest,
  workflow run report, proof package, verifier report, workflow receipt).
- `validate_runtime_proof_parity_report(&RuntimeProofParityReport) -> Result<(), RuntimeProofParityError>`
- `validate_runtime_proof_regeneration_artifacts(RuntimeProofRegenerationArtifacts<'_>) -> Result<(), RuntimeProofParityError>`
- `RuntimeProofParityError::Rejected { code, detail }`, with `.code()` and
  `.detail()` accessors.
- Schema constants: `CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA`,
  `CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA`,
  `CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA`,
  `CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA`,
  `CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA`.

## Testing

`cargo test -p chio-runtime-proof-parity`

## See also

- `chio-runtime-core` - re-exports `RuntimeProofParityReport` /
  `RuntimeProofParityMismatch` and validates parity reports through
  `validate_runtime_proof_parity_report`; it keeps its own separate type and
  validator for regeneration-artifact bundles rather than using this crate's.
- `chio-proof-room` - validates runtime-parity report nodes and
  regeneration-artifact bundles sourced from a runtime evidence graph, using
  both validators in this crate.
- `chio-core-types` - supplies the canonical JSON encoding and sha256 hashing
  every check is built on.
