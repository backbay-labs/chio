# hello-receipt-verify Architecture Notes

## Module Boundaries

This example owns the minimal offline evidence-verification path. It does not
start trust-control, issue capabilities, run an app, or mint fresh receipts.
Its checked-in `fixtures/minimal-evidence/` directory is the product surface:
a captured evidence export with one tool receipt, one capability-lineage
record, no checkpoints, and an explicit `admin_all` read boundary. `smoke.sh`
copies that fixture into an artifact directory, runs `chio evidence verify`,
generates a compact summary, tampers with a copied package, and proves
offline verification fails.

There is no crate or package-manager manifest. The example depends only on the
workspace `chio` binary and Python's standard library for local artifact
inspection.

## Pain Points

The smoke script currently inlines package inspection, summary generation, and
tamper-error assertions. Those checks are too shallow for the evidence bundle
as a teaching artifact: they do not verify manifest file hashes, query read
boundary, receipt/lineage consistency, receipt semantics, or summary drift as
one offline package contract.

The tamper assertion has also drifted from the current CLI JSON error shape.
The verifier now reports the registry string code under
`context.string_code`; the old `context.legacy_string_code` assertion makes
the smoke fail even though tamper detection itself still works.

## Security And API Constraints

- Preserve this as an offline-only verifier example. Do not add live
  trust-control, app, sidecar, or receipt-minting steps.
- Preserve the checked-in fixture's explicit `admin_all` read boundary as a
  captured operator export. The example verifies that boundary; it does not
  teach implicit cross-tenant reads.
- Preserve manifest-backed tamper detection: changing any covered file must
  make `chio evidence verify` fail.
- Preserve signed artifact compatibility by treating the checked-in evidence
  package as immutable test input unless the export format itself changes.

## Affected Dependents

`examples/run-hello-smokes.sh` invokes this smoke by name, so it is the direct
dependent gate. `examples/README.md` and `examples/EXAMPLE_SURFACE_MATRIX.md`
describe the same offline-verification surface and need no update unless the
file set or behavior changes.

No crate API or shared helper edits are planned.

## Planned Material Improvement

Add a package-owned verifier that validates the fixture and smoke artifacts as
one offline evidence contract: manifest hash coverage, `admin_all` query
boundary, receipt count, uncheckpointed receipt count, receipt semantics,
receipt/lineage capability consistency, summary consistency, and current
tamper-error shape. Update `smoke.sh` so shell code only orchestrates CLI
verification and tampering, while the verifier owns artifact validation and
summary generation. Add focused unit tests for valid fixture verification,
tamper-error validation, summary drift, manifest hash mismatch, and
receipt/lineage mismatch.
