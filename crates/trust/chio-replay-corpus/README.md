# chio-replay-corpus

`chio-replay-corpus` turns captured TEE frames into the deterministic fixture
format Chio's replay gate consumes. Given a batch of `chio_tee_frame::Frame`s
for one scenario, it deduplicates them by canonical invocation hash,
re-redacts payload bytes under the current default redactor set, and writes a
`<family>/<name>` fixture directory. It also builds and signs the `tee.bless`
audit event that records each graduation.

Frame capture and first-pass redaction happen in `chio-tee`; the frame wire
format is defined in `chio-tee-frame`. This crate only normalizes and blesses
already-captured frames into replay fixtures; it does not run a TEE session.

## Responsibilities

- Compute the canonical-invocation dedupe key (RFC 8785 canonical JSON +
  SHA-256) and collapse duplicate frames, last occurrence wins.
- Re-run the current default redactor set over payload bytes, independent of
  whichever pass id the frame was captured with, and drop unstable timing
  metadata before a frame is blessed.
- Validate a `<family>/<name>` target directory and stage-and-write the
  three-file fixture shape: `receipts.ndjson`, `checkpoint.json`, `root.hex`.
- Build, validate, sign, and append the `tee.bless` audit event to a JSONL
  receipt store.

## Public API

- `dedupe::{dedupe_last_wins, invocation_hash, DedupedFrame}` - canonical
  invocation hashing and last-wins dedupe over `chio_tee_frame::Frame`.
- `reredact::{reredact_default, ReredactedPayload}` - stable re-redaction
  under the current default pass.
- `fixture_writer::{write_fixture, scenario_from_dir, validate_scenario_dir,
  FixtureSummary, ReplayScenario, ByteSizes, WriterError, RECEIPTS_FILENAME,
  CHECKPOINT_FILENAME, ROOT_FILENAME}` - fixture-directory validation and
  write.
- `audit::{TeeBlessAuditBody, TeeBlessAuditEntry, BlessOperator,
  BlessCapture, BlessFixture, write_tee_bless_audit_entry, BlessAuditError,
  TEE_BLESS_EVENT, TEE_BLESS_CAPABILITY}` - signed `tee.bless` audit trail.
- `DEFAULT_REDACTION_PASS_ID` - re-export of
  `chio_tee::DEFAULT_REDACTION_PASS_ID`.
- `ReplayCorpusError`, `Result<T>` - crate-level error enum and alias.

## Testing

`cargo test -p chio-replay-corpus`

## See also

- `chio-tee` - captures and redacts TEE frames; supplies the default redactor
  pass `reredact_default` re-runs.
- `chio-tee-frame` - defines the `Frame` type this crate dedupes and writes.
- `chio-cli` - `chio replay --bless --into <fixture-dir>` drives
  `write_fixture` and the audit helpers from the command line.
- `chio-arena` - auto-promotes arena scenario runs into fixtures via
  `write_fixture`.
- `chio-lineage` - ingests `receipts.ndjson` rows into its own row shape (not
  a crate dependency) to build an offline lineage DAG.
