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
