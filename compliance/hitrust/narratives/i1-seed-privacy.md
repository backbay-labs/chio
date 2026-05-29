# Privacy Practices Narrative

Privacy evidence in the repository covers receipt and log redaction
(`crates/chio-log-redact/src/lib.rs`), the audit-log export schema
(`spec/audit-log/export-schema.v1.json`), and the documented
minimum-necessary and telemetry de-identification posture
(`compliance/hitrust/policies/de-identification.md`).

This family is self-assessed as partial: redaction is implemented and
the de-identification policy is documented, but BAA constraints and PHI
handling are out-of-tree and not held in this repository.

Fail-closed note: PHI-bearing samples are never uploaded to this
repository, and BAA-dependent rows remain gaps until out-of-tree
references exist.
