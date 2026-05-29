# Chio Eval Receipt Schemas

This directory contains wire-adjacent schemas for AI-lab evaluation
artifacts. These schemas wrap Chio wire receipts for partner eval
pipelines without changing the inner `chio-wire/v1/receipt` body.

## `chio.eval-report.bundle.v1`

`receipt-format.v1.json` defines the eval-report bundle envelope.
The bundle:

- preserves each inner Chio receipt payload;
- carries partner eval metadata in `eval_run`;
- pins the verdict-matrix `corpus_sha256`;
- signs the bundle without its `signatures` field after `rfc8785`
  canonicalization;
- supports deterministic local test signatures for fixtures and
  partner-review samples.

The bundle parser today accepts only the local `test-sha256` signature
kind. Real partner cryptographic attestation is not yet claimed; cosign
+ GitHub OIDC and PGP detached lanes are tracked as backlog work for a
future v3.x release. Until those lanes land, the schema enum and the
verifier are intentionally aligned on a single closed allow-list and
any other `kind` value is rejected fail-closed.
