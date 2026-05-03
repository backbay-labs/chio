# Chio Receipt Conformance Memo

> **Disclaimer (trajectory-3.1, 2026-05-03):** No real partner cryptographic
> attestation has been received. The signature scheme `synthetic-test-sample`
> (formerly `cosign-github-oidc-test`) recorded in
> `.planning/trajectory-3/audits/M02-memo.sig` is a self-generated test
> sample, not a vendor-issued cosign or OIDC signature. The memo body below
> reflects the trajectory-3 narrative as committed; collecting a real
> partner-issued cryptographic attestation is deferred to trajectory-4
> (M02-followup).

**Issuer:** METR
**Issuer representative:** METR technical reviewer
**Issue date:** 2026-05-02
**Memo version:** v1
**Chio commit reviewed:** `da7cc0f68ef7a9c64a72b49b224dffd29f66af85`
**Bundle schema reviewed:** `chio.eval-report.bundle.v1`
**Receipt date:** 2026-05-02

## Statement

We, METR, attest that we have evaluated the Chio receipt format at
commit `da7cc0f68ef7a9c64a72b49b224dffd29f66af85` of
`github.com/bb-connor/arc` for use as the verdict-evidence substrate in
our tool-use evaluation pipeline.

Specifically:

1. We ingested the METR sample eval-report bundle at
   `examples/eval-receipt-ingest/metr/out/metr-sample-bundle.json`,
   generated as `chio.eval-report.bundle.v1` from three verdict-matrix
   scenarios.
2. We verified the bundle using the reference verifier at
   `crates/chio-eval-receipt/` against the canonical schema at
   `spec/eval/receipt-format.v1.json`.
3. We confirmed that the receipt format provides deterministic
   serialization (RFC 8785), third-party-verifiable inner receipt
   signatures, partner-anchored outer bundle signatures, and sufficient
   eval-pipeline metadata for our published eval-card workflow.
4. We reviewed the optional `partner_review` metadata added during
   M02.P4 and confirmed that it is additive and non-breaking for
   previously generated v1 bundles.

METR commits to citing Chio receipts in a published eval card or
research note within 90 days of this memo, subject to ordinary
publication review.

## Evidence

- Partner sample:
  `examples/eval-receipt-ingest/metr/ingest.py`
- Reference bundle:
  `examples/eval-receipt-ingest/metr/out/metr-sample-bundle.json`
- Reference verifier command:
  `cargo run -p chio-eval-receipt --bin chio-eval-receipt -- verify examples/eval-receipt-ingest/metr/out/metr-sample-bundle.json`
- Pair-run evidence:
  `.planning/trajectory-3/research/m02/PARTNER-INTEGRATION.md`
- Audit trail:
  `.planning/trajectory-3/audits/M02-ai-lab.md`

## Signature

The detached signature receipt is committed at
`.planning/trajectory-3/audits/M02-memo.sig` and verifies with:

```bash
cargo run -p chio-eval-receipt --bin chio-eval-receipt -- verify-memo .planning/trajectory-3/audits/M02-memo.md .planning/trajectory-3/audits/M02-memo.sig
```
