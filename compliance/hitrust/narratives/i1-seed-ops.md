# Communications and Operations Management Narrative

Operations evidence in the repository includes the audit-log export
schema (`spec/audit-log/export-schema.v1.json`), the receipt pipeline
(`crates/chio-kernel/src/receipt_store.rs`), and hosted CI
(`.github/workflows/ci.yml`).

This family is self-assessed as partial: schema, receipts, and CI exist,
but 30-day production operational samples have not been pulled. See
`compliance/hitrust/operational-samples.md` for the sample plan and that
open gap.

Fail-closed note: sample-dependent rows remain gaps until real samples
are produced.
