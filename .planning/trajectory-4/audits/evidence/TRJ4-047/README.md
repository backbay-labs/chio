# TRJ4-047 Evidence - weights_hash_spoof Linkage

## Scope

`spec/security/chio-threat-model.v1.json` now gives the already-covered
`weights_hash_spoof` row explicit `coveredBy` linkage.

## Linked Tests

- `crates/chio-conformance/tests/threats/weights_hash_spoof.rs`
- `crates/chio-kernel/tests/weights_binding.rs`
- `crates/chio-weights/tests/lineage_anchor.rs`
- `crates/chio-weights/tests/equivalence.rs`

## Validation

- `bash scripts/check-threat-coverage.sh` passed: 12 covered, 0 partial, 8
  pending, 0 uncovered.
