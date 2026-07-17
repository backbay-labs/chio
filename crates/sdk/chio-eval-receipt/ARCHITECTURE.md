# chio-eval-receipt architecture

## Overview

`chio-eval-receipt` is an SDK-layer crate, not a kernel component: its only
`chio-*` dependency is `chio-core-types`, and it forbids `unsafe_code`. It
owns both directions of a `chio.eval-report.bundle.v1` bundle: an unsigned
exporter that wraps verdict-matrix scenario receipts, and a fail-closed
verifier that admits, corpus-checks, hash-checks, and signature-checks a
bundle document end to end.

It does not own the verdict-matrix corpus itself
(`crates/tooling/chio-conformance`), partner trace ingestion, or the inner
Chio receipt schema (`chio-core-types`). Real partner cryptographic
attestation is not implemented: production signature verification
(`verify_bundle`) currently accepts no signature `kind`, including the
fixture scheme.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Declares `export` and `verify` as public modules, re-exports their public items at the crate root, and defines `BUNDLE_SCHEMA_ID` / `BUNDLE_SCHEMA_PATH`. |
| `src/export.rs` | Typed, validated construction of `EvalRunMeta` and `Receipt` inputs; `export_scenario_run` assembles an unsigned `Bundle`; crate-shared `sha256_hex` helper. |
| `src/verify.rs` | JSON parsing, closed-schema envelope admission, corpus pin check, receipt hash and inner-signature check, partner-review check, outer-signature check. |
| `src/bin/cli.rs` | `chio-eval-receipt` binary: `verify`, `verify-fixture`, `verify-memo` subcommands. |
| `py/src/lib.rs` | PyO3 module `chio_eval_receipt_py` wrapping `verify_bundle`. |

## Bundle lifecycle

1. **Export** - `export_scenario_run` copies validated `EvalRunMeta` and
   per-scenario `Receipt`s into a `Bundle`, hashing each preserved receipt
   payload into `receipt_sha256` and pinning `corpus` to the compiled-in
   verdict-matrix constants. `signatures` is always empty; the exporter
   never signs.
2. **Sign** (external to this crate) - a caller attaches one or more outer
   signatures over the RFC 8785 canonical form of the bundle with
   `signatures` removed. `test_signature_for_bundle_json` computes the
   deterministic `test-sha256` variant used by fixtures and the golden
   vector.
3. **Verify** - `verify_bundle` / `verify_fixture_bundle` parse the JSON, run
   `verify_schema_envelope` (closed field sets, required fields, enum and
   SHA-256-shape checks) before trusting any content, then check the corpus
   pin, every receipt's hash and embedded `ChioReceipt` signature, the
   optional `partner_review` block, and finally the outer signature(s).

## Invariants and failure modes

- Schema admission runs before signature trust: `verify_schema_envelope`
  rejects unknown fields, missing required fields, and invalid enum values
  (`eval_run.pipeline_language`, `receipts[].verdict`,
  `partner_review.disposition`) before any hash or signature is checked, so
  a valid fixture signature cannot bless a field the schema forbids.
- `corpus.corpus_sha256` and `corpus.scenario_count` must equal
  `VERDICT_MATRIX_CORPUS_SHA256` / `VERDICT_MATRIX_SCENARIO_COUNT`; any other
  verdict-matrix corpus is rejected.
- Every `receipts[]` entry must reproduce its declared `receipt_sha256` and
  carry an inner payload that verifies under
  `ChioReceipt::verify_signature`. Fixture mode additionally allows a closed,
  hardcoded set of three `(scenario_id, payload sha256)` pairs
  (`LOCAL_TEST_RECEIPT_FIXTURE_HASHES`) to skip that check; tampering with a
  fixture payload changes its hash and drops it out of the allowlist.
- Outer signature verification requires `signed_payload ==
  "bundle_without_signatures:rfc8785"` and recomputes the RFC 8785 canonical
  hash itself rather than trusting a caller-supplied one. Production mode
  (`verify_bundle`) accepts no signature `kind` today, including
  `test-sha256`; that kind only verifies under `verify_fixture_bundle`.
- `export_scenario_run`'s typed constructors (`EvalRunMeta::from_parts`,
  `Receipt::from_parts`) reject empty or whitespace-padded identity fields at
  construction time. `receipt_payload` is checked only for emptiness, so its
  bytes are preserved exactly, padding included.
- The crate forbids `unsafe_code` (`#![forbid(unsafe_code)]`).

## Dependencies

`chio-core-types` supplies RFC 8785 canonicalization (`canonicalize`) and the
inner receipt type and signature check (`receipt::body::ChioReceipt`); it is
a direct, unaliased dependency (`chio_core_types::`, not a `chio_core`
facade). `serde_json` parses and canonicalizes bundle documents. `sha2`
computes payload and signature hashes. `py/` (`chio-eval-receipt-py`) depends
on this crate by path and adds `pyo3`.
