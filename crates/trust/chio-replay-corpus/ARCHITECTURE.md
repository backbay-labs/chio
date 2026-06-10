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
- Public struct fields and helper names are already consumed by replay and bless tooling, so validation tightens without changing the wire shape.
- `TeeBlessAuditBody::validate` enforces writer-compatible root and capture-count invariants before signing: a 64-character lowercase hex `fixture.receipts_root` and a nonzero capture count, so a signed bless audit cannot claim a fixture state the writer itself could never produce.

## Verification Focus

- Determinism is the headline test target: re-redaction, canonical receipt
  encoding, root calculation, and pass-ID sorting must produce identical fixture
  bytes across machines, so coverage re-runs the writer on captured frames and
  compares the output byte-for-byte.
- Audit signing and verification are exercised against malformed bodies,
  noncanonical roots, and zero-capture claims to confirm `validate` rejects them
  before a signature is produced.
- Fixture directory validation is tested with path-traversal and non-fixture
  entries to prove the replay-gate shape is enforced rather than assumed.
