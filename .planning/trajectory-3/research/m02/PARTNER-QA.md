# M02 Partner Q&A

**Date:** 2026-05-02
**Partner:** METR
**Partner slug:** `metr`
**Trajectory:** trajectory-3
**Milestone:** M02

This file records the week-1 acceptance-criteria Q&A for the METR
eval-report bundle integration. It is the P1 input to the P2 export
contract and the P3 bundle schema.

## Summary

| Topic | Partner reply | M02 consequence |
|-------|---------------|-----------------|
| signature scheme | Use cosign + GitHub OIDC for the default signed memo and signed bundle examples. Keep PGP detached signatures as an explicitly documented fallback if the partner reviewer cannot use OIDC for the final memo. | P3 schema keeps `sigstore-cosign` and `pgp-detached` as accepted signature kinds. P5 memo defaults to cosign. |
| ingest pipeline language | Python is the review language for the first METR ingest spike because the bundle can be loaded alongside vivaria trace post-processing. Go is out of P4 scope unless the partner asks for a second sample. | P4 creates `examples/eval-receipt-ingest/metr/` as a Python sample, while the Rust verifier remains the reference implementation. |
| eval-card citation window | METR will review the P5 conformance memo within 7 days of the P5 close target. A public eval-card citation is best-effort after publication review and is not a trajectory-3 close blocker unless written into the final memo. | D15 freshness applies to the signed memo receipt, not to a public blog publication date. P5 records the citation URL if available. |

## Questions And Replies

### 1. Which signature scheme should the bundle and final memo use?

**Reply:** Default to cosign with GitHub OIDC. This keeps the signer
identity bound to the repository release workflow and avoids manual
key-distribution setup during the eval review. PGP detached signatures
remain acceptable only as a fallback for a partner-owned signing key.

**Recorded decision:** P3 will model signature entries with an explicit
`kind` field and will include `sigstore-cosign` plus `pgp-detached` as
accepted values. P5 uses cosign unless METR requests the fallback in
writing.

### 2. Which ingest pipeline language should the partner sample target?

**Reply:** Python. The first partner review path is a vivaria trace
post-processing step that loads one eval-report bundle, verifies the
outer signature, verifies every inner receipt, and emits a compact
verdict summary.

**Recorded decision:** P4 ships the METR sample under
`examples/eval-receipt-ingest/metr/` as a Python script. The sample
must not require a live METR deployment; it consumes the golden bundle
fixture and mirrors the post-run trace ingest shape.

### 3. What citation window should M02 promise?

**Reply:** The partner can commit to reviewing and signing the P5
conformance memo inside the D15 7-day freshness window. A public
eval-card citation depends on publication review and should be recorded
as evidence if available, but it should not block the M02 close unless
the final conformance memo makes it part of the acceptance criteria.

**Recorded decision:** The P5 closeout requires the signed conformance
memo and signature. The public partnership note carries TODO fields
for memo URL, memo hash, signature path, and any public citation URL.

## Freshness

This Q&A is dated 2026-05-02. P2 and P3 may rely on it without a
refresh only while the D15 7-day evidence freshness window remains
valid. Any material partner change after that date must append a new
evidence-log row in `.planning/trajectory-3/audits/M02-ai-lab.md`.
