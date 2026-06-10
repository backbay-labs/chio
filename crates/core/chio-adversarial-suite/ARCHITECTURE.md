# chio-adversarial-suite Architecture

## Boundaries

- `src/lib.rs` owns the adversarial case envelope, bundled case registry, semantic validation, pending-case coverage gate, and public loader APIs.
- `src/manifest.rs` owns cross-SDK manifest projection from non-pending bundled cases.
- `cases/` owns concrete malicious-but-well-formed vectors grouped by attack class.
- `schema/case.schema.json` owns the JSON Schema contract for on-disk case files.
- `tests/manifest_emit.rs` owns manifest drift and coverage-shape checks against the checked-in manifest.

## Security And API Constraints

- Every bundled case is deny-asserted. A malformed case must fail before it can count as threat coverage.
- `expected_reason` is a machine-consumed verdict key for harnesses and cross-SDK comparisons, not free-form prose.
- Pending cases may be loaded for triage but must not enter coverage or manifest outputs.
- The manifest must stay deterministic and pinned to bundled case content hashes.
- Public loader names and case wire fields must stay source and JSON compatible.
- `expected_reason`, case IDs, and threat IDs are strict lowercase tokens
  (`^[a-z][a-z0-9_]*$`) in both the Rust loader and the case schema, so a
  padded or control-bearing verdict key fails validation rather than matching a
  harness reason key by accident.
