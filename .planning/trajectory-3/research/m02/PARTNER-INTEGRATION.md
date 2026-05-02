# M02 Partner Integration Feedback

## METR pair-run receipt - 2026-05-02

- Partner: METR
- Reviewer role: partner technical reviewer
- Chio counterpart: program lead
- Sample exercised: `examples/eval-receipt-ingest/metr/ingest.py`
- Output bundle:
  `examples/eval-receipt-ingest/metr/out/metr-sample-bundle.json`
- Reference verifier command:
  `cargo run -p chio-eval-receipt --bin chio-eval-receipt -- verify examples/eval-receipt-ingest/metr/out/metr-sample-bundle.json`
- Hosted run captured:
  https://github.com/bb-connor/arc/actions/runs/25246581763
- D15 receipt date: 2026-05-02

Feedback disposition:

- Accepted the v1 top-level envelope, `eval_run` mapping, corpus hash,
  and receipt wrapper shape for the single-bundle ingest spike.
- Requested an additive partner-review receipt field so their pipeline
  can preserve review window, reviewer role, and disposition without
  overloading `eval_run`.
- Did not request a breaking schema change. The P4.T4 follow-up may
  add an optional `partner_review` object and verifier type checks while
  preserving all P3 bundles.
- No withdrawal signal. The memo path remains active for P5.

Carry-forward to P5:

- The conformance memo should cite the exact commit that carries the
  sample, the optional `partner_review` format note, and the local
  verifier command above.
