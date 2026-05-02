# Partnership Note Draft: METR Eval-Receipt Review

**Status:** draft placeholder for M02.P5
**Partner:** METR
**Partner slug:** `metr`
**Trajectory:** trajectory-3
**Milestone:** M02

TODO: Replace this draft with the public partnership note or README
entry after the P5 conformance memo is received and signed.

## Working Headline

Chio eval-report receipts reviewed for METR-compatible tool-use eval
ingest

## Draft Copy

Chio now publishes `chio.eval-report.bundle.v1`, a signed eval-report
bundle format that wraps kernel-signed Chio receipts without changing
their inner receipt body. The format lets an AI-lab evaluation pipeline
batch-verify tool-use decisions, cite a stable verdict-matrix corpus
hash, and attach partner-side run metadata for reproducible eval-card
review.

For the M02 trajectory-3 milestone, METR reviewed the single-bundle
ingest path, the reference verifier shape, and the conformance memo
that records what a partner can verify from the public artifacts.

## Evidence Placeholders

- TODO: Signed memo URL:
  `.planning/trajectory-3/audits/M02-memo.md`
- TODO: Signed memo sha256: `<filled at M02.P5.T2>`
- TODO: Detached signature path:
  `.planning/trajectory-3/audits/M02-memo.sig`
- TODO: Signature scheme and signer identity:
  `sigstore-cosign` with GitHub OIDC unless the partner requests the
  PGP fallback.
- TODO: Eval-report bundle schema URL:
  `spec/eval/receipt-format.v1.json`
- TODO: Golden bundle vector hash:
  `tests/bindings/vectors/eval/v1.json`
- TODO: Partner sample path:
  `examples/eval-receipt-ingest/metr/`
- TODO: Public eval-card citation URL, if available:
  `<partner-publication-url-or-not-applicable>`

## Publication Checklist

- TODO: P3 schema and verifier merged.
- TODO: P4 METR ingest sample runs locally and in CI.
- TODO: P5 conformance memo received within the D15 7-day freshness
  window.
- TODO: Audit doc points to the final partnership note URL.
- TODO: `releases.toml` activation evidence references the memo if the
  release gate consumes M02 before trajectory close.

## Notes For P5 Editor

Keep the final copy bounded to what the signed memo actually attests.
Do not claim broad METR adoption, production deployment, or public
eval-card citation unless the partner provides that evidence in the P5
memo or a linked publication.
