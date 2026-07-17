# chio-replay-corpus architecture

## Overview

`chio-replay-corpus` is a pure library (no async runtime, no network I/O)
that sits between TEE capture and the replay gate. Frames from `chio-tee`
already carry a capture-time redaction pass id, but the bless step re-runs
the current default redactor set over each surviving frame rather than
trusting that pass, so a fixture blessed today reflects today's redaction
coverage even for an older capture. The crate turns a batch of
already-captured `chio_tee_frame::Frame`s into the on-disk fixture format
(`receipts.ndjson`, `checkpoint.json`, `root.hex`) the replay gate treats as
ground truth, and `audit.rs` adds a signed record of who blessed which
capture into which fixture. Determinism is the design goal: dedupe,
re-redaction, canonical receipt encoding, and root hashing are all pinned so
identical input frames produce byte-identical fixture bytes on any machine.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public re-export surface, `ReplayCorpusError`, the crate `Result` alias, and the `DEFAULT_REDACTION_PASS_ID` re-export. |
| `src/dedupe.rs` | Canonical invocation hash (RFC 8785 JSON + SHA-256) and last-wins dedupe over a frame stream. |
| `src/reredact.rs` | Re-runs `chio_tee::RedactPass::with_default()` / `RedactClass::default_full()` and normalizes the result, dropping unstable timing metadata. |
| `src/fixture_writer.rs` | Scenario-directory parsing and shape validation, receipt stripping, checkpoint construction, root hashing, stage-and-rename fixture commit. |
| `src/audit.rs` | `TeeBlessAuditBody` / `TeeBlessAuditEntry` construction, fail-closed validation, Ed25519 signing and verification, append-only JSONL persistence. |

## Bless pipeline

1. `validate_scenario_dir` parses the `<family>/<name>` target suffix and
   confirms the directory is absent, empty, or already fixture-shaped.
2. `dedupe_last_wins` collapses the input frames by canonical invocation
   hash; the last occurrence in input order survives.
3. Each surviving frame's `invocation` is re-redacted under the current
   default pass (`reredact_default`) and stripped to `{invocation, verdict,
   deny_reason, would_have_blocked}`, dropping capture-only fields
   (`tenant_sig`, blob hashes, timing).
4. Stripped receipts are canonical-JSON-encoded, newline-joined into the
   receipts buffer, and their redaction pass ids collect into a sorted set.
5. `checkpoint.json` is built (schema markers, scenario id, frame counts,
   sorted pass ids) and canonically encoded; `root.hex` is
   `SHA-256(receipts-without-trailing-newline || checkpoint bytes)` as
   lowercase hex.
6. All three files stage as `.tmp`, fsync, and rename into place; the final
   directory is re-verified to contain exactly `receipts.ndjson`,
   `checkpoint.json`, `root.hex`.
7. Callers may then build a `TeeBlessAuditBody`, sign it with
   `TeeBlessAuditEntry::sign`, and append it via
   `write_tee_bless_audit_entry` to record who ran the bless.

## Invariants and failure modes

- `write_fixture` fails closed on an empty capture, before or after dedupe
  (`WriterError::EmptyCapture`).
- The target directory must match a two-segment, non-traversing,
  `[A-Za-z0-9_.-]+` `<family>/<name>` suffix; `scenario_from_dir` rejects
  `..` components and non-UTF-8 segments.
- A pre-existing target may be empty or hold a subset of the three fixture
  filenames; any other entry fails closed as `ExtraEntry`. After a
  successful write the directory must contain exactly the three files,
  which `write_fixture` re-verifies post-commit.
- Fixture commit stages each file (`.tmp` write + fsync) then renames it
  into place; a rename failure mid-commit can leave a partial fixture on
  disk without rolling back files already renamed.
- Re-redaction fails closed: a `RedactError`, or a redacted invocation that
  no longer parses as JSON (`RedactedInvocationJson`), aborts the whole
  `write_fixture` call.
- Determinism: the dedupe key, canonical receipt bytes, and the
  `BTreeSet`-sorted `redaction_pass_ids` are all order-independent, so
  `root_hex` is stable across machines given the same input frames.
- `TeeBlessAuditBody::validate` fails closed before signing: pinned `event`
  and `control_plane_capability` values, non-blank/non-padded string
  fields, a 64-character lowercase-hex `receipts_root`, nonzero capture
  counts, and `frames_after_dedupe <= frames_in` /
  `frames_after_redact <= frames_after_dedupe`. `TeeBlessAuditEntry::sign`
  always validates before signing.
- Signatures are pinned to an `ed25519:<hex>` envelope; `verify_signature`
  rejects any other prefix before attempting to decode.

## Dependencies

Internal: `chio-core-types` (imported as `chio_core`; `Cargo.toml` aliases
it via `chio-core = { package = "chio-core-types", ... }`) supplies
canonical JSON encoding, SHA-256 hashing, and Ed25519 signing (`Keypair`,
`PublicKey`, `Signature`). `chio-tee` supplies the default redactor pass
(`RedactPass`, `RedactClass`, `RawPayloadBuffer`, `RedactError`,
`DEFAULT_REDACTION_PASS_ID`) re-run by `reredact_default`. `chio-tee-frame`
supplies the `Frame` type and `FRAME_VERSION` this crate dedupes, strips,
and records in checkpoints. External: `serde` / `serde_json` for the audit
and checkpoint schemas, `sha2` for root hashing, `hex` for hex encoding,
`thiserror` for error types.
