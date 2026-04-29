# Chio Replay CLI Runbook

This file is the M10 operator runbook for `chio replay --bless`. The
long-form CLI reference remains in `docs/cli/replay.md`.

## Bless Graduation

The graduation pipeline is:

```text
capture -> redact -> dedupe -> review -> bless
```

1. The tee writes shadow-mode capture frames under
   `${CHIO_TEE_RUNTIME_DIR}/captures/<run_id>.ndjson`.
2. Each frame has already passed through the default redactor before it is
   persisted. The frame records `redaction_pass_id`.
3. `chio replay <capture.ndjson> --bless --into <fixture-dir>` re-redacts
   the invocation under the current default redactor set, dedupes by the
   canonical JSON invocation hash with last-wins semantics, and writes the
   M04 replay-gate fixture shape:

   ```text
   tests/replay/fixtures/<family>/<name>/
     receipts.ndjson
     checkpoint.json
     root.hex
   ```

4. The writer strips `tenant_sig`, `request_blob_sha256`, and
   `response_blob_sha256`. The blessed receipt stream retains only the
   redacted canonical invocation and verdict fields.
5. The resulting fixture must be acceptable to the M04 replay gate before
   it is committed.

## Bless Audit Entry

Every bless appends a canonical JSON `tee.bless` event to the receipt
store. The signature covers the canonical JSON body without the `signature`
field and is encoded as `ed25519:<hex>`.

Required fields:

```json
{
  "event": "tee.bless",
  "ts": "2026-04-25T18:02:11.418Z",
  "operator": {
    "id": "did:web:integrations.chio.dev:alice",
    "git_user": "alice@chio.dev"
  },
  "capture": {
    "path": "captures/01JTEE00000000000000000000.ndjson",
    "frames_in": 1234,
    "frames_after_dedupe": 987,
    "frames_after_redact": 987
  },
  "fixture": {
    "family": "openai_responses_shadow",
    "name": "tool_call_with_pii",
    "path": "tests/replay/fixtures/openai_responses_shadow/tool_call_with_pii/",
    "receipts_root": "a917b3c1..."
  },
  "redaction_pass_id": "m06-redactors@1.4.0+default",
  "control_plane_capability": "chio:tee/bless@1",
  "signature": "ed25519:..."
}
```

Review checklist:

- Operator DID is a real `did:web` identity for the reviewer or
  integration operator.
- `frames_in`, `frames_after_dedupe`, and `frames_after_redact` match the
  bless output.
- `fixture.path` matches the committed fixture directory.
- `fixture.receipts_root` matches the committed `root.hex`.
- `redaction_pass_id` is the current default redactor pass.
- The Ed25519 signature verifies over the canonical JSON body.

## 30-Day Capture Expiry

Unreviewed `chio-tee-corpus` capture releases expire after 30 days.
Reviews run every Tuesday at 14:00 UTC. The scheduled workflow is
`.github/workflows/chio-tee-corpus-expire.yml`.

Posture:

- The Tuesday cron deletes only expired, unreviewed releases whose tag or
  release name starts with `chio-tee-corpus/`.
- A release is treated as reviewed when its release notes contain either
  `chio-tee-review: approved` or `reviewed=true`.
- Manual `workflow_dispatch` defaults to dry-run. Maintainers must set
  `delete_expired=true` to perform deletion from a manual run.
- Deletion removes the GitHub release entry. It does not rewrite committed
  replay fixtures, pins, or audit entries.

If a capture still needs review after 30 days, refresh it into a new
`chio-tee-corpus/<id>` release with updated notes instead of mutating the
expired release.
