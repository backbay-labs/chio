# chio-eval-receipt

`chio-eval-receipt` is the M02 reference-verifier crate for
`chio.eval-report.bundle.v1`.

P0 intentionally ships only the workspace shell and stable descriptor:

- schema id: `chio.eval-report.bundle.v1`
- planned schema path: `spec/eval/receipt-format.v1.json`
- initial partner lane: METR
- current stage: `p0-placeholder`

The placeholder fails closed: `EvalReceiptSurface::verifier_ready()`
returns `false` until P3 lands schema validation, bundle verification,
and the CLI.

Planned follow-up tickets:

- M02.P2 adds export-contract documentation and verdict-matrix mapping.
- M02.P3 adds schema validation, signature verification, CLI support,
  Python binding scaffolding, and golden vectors.
- M02.P4 adds the partner ingest sample under
  `examples/eval-receipt-ingest/`.
