# Chio Eval Receipt Schemas

This directory contains wire-adjacent schemas for AI-lab evaluation
artifacts. These schemas wrap Chio wire receipts for partner eval
pipelines without changing the inner `chio-wire/v1/receipt` body.

## `chio.eval-report.bundle.v1`

`receipt-format.v1.json` defines the M02 eval-report bundle envelope.
The bundle:

- preserves each inner Chio receipt payload;
- carries partner eval metadata in `eval_run`;
- pins the verdict-matrix `corpus_sha256`;
- signs the bundle without its `signatures` field after `rfc8785`
  canonicalization;
- supports deterministic local test signatures for fixtures and
  partner-review samples.

The bundle parser today accepts only the local `test-sha256` signature
kind. Trajectory-3.1 retracted real partner cryptographic attestation
(see `.planning/trajectory-3/audits/M02-ai-lab.md` disclaimer); cosign
+ GitHub OIDC and PGP detached lanes are deferred to trajectory-4
(M02-followup). Until those lanes land, the schema enum and the
verifier are intentionally aligned on a single closed allow-list and
any other `kind` value is rejected fail-closed.
