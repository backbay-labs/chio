# chio-replay-corpus Architecture

## Boundaries

- `src/dedupe.rs` owns canonical invocation hashing and last-wins dedupe for captured TEE frames.
- `src/reredact.rs` owns re-running the current default redactor set and stripping unstable timing metadata.
- `src/fixture_writer.rs` owns fixture directory validation, capture-to-replay receipt normalization, checkpoint generation, root calculation, and atomic fixture writes.
- `src/audit.rs` owns signed `tee.bless` audit bodies, signature verification, and append-only JSONL persistence.
- `src/lib.rs` re-exports the public helper surface for bless and replay callers.

## Security And API Constraints

- Fixture bytes must stay deterministic across machines: canonical JSON receipts, stable re-redaction output, lowercase hex roots, and sorted redaction pass IDs.
- Bless audit entries are signed canonical JSON. Invalid audit bodies must fail before signing.
- Fixture directories must keep the exact replay-gate shape and must not accept path traversal or non-fixture entries.
- Public struct fields and helper names are already consumed by replay and bless tooling, so validation should tighten without changing the wire shape.

## Pain Points

- The fixture writer rejects empty captures and writes 64-character lowercase hex roots, but the audit signer currently accepts malformed `fixture.receipts_root` values and zero capture counts.
- That lets a signed bless audit claim a fixture state the writer itself could never produce.

## Planned Improvement

Make `TeeBlessAuditBody::validate` enforce writer-compatible root and capture-count invariants before signing.
