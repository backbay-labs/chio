# chio-eval-receipt Architecture

## Boundary

`chio-eval-receipt` owns the reference Rust verifier and unsigned exporter for
`chio.eval-report.bundle.v1`. It preserves inner Chio receipt payloads, checks
the eval corpus pin, verifies fixture or production bundle signatures, and
exposes a small CLI plus Python binding surface. It does not own the verdict
matrix corpus, partner trace ingestion, real cosign or PGP verification, or the
inner Chio receipt schema.

## Module Boundaries

- `export` owns typed construction of unsigned bundle inputs and SHA-256 hashes
  over preserved receipt payload bytes.
- `verify` owns JSON bundle admission, corpus verification, receipt payload
  verification, partner-review checks, and bundle signature checks.
- `src/bin/cli.rs` owns filesystem and command-line parsing around the library
  verifier.
- `py/` owns the PyO3 wrapper that calls the Rust production verifier.
- `xtask/src/eval_receipt_regen.rs` is a dependent generator for the golden
  eval binding vector.

## Schema Admission

`spec/eval/receipt-format.v1.json` is a closed schema at the root and nested
object levels. `verify` runs a schema-envelope admission pass before corpus,
receipt, and signature checks: it rejects unknown object fields, missing
required sections, empty required strings, and invalid closed-enum values. This
admission boundary runs before the `test-sha256` fixture signature is trusted,
so a recomputed local fixture signature cannot bless fields the schema forbids.

## Security And API Constraints

- Preserve the public `verify_bundle`, `verify_fixture_bundle`,
  `test_signature_for_bundle_json`, and export helper APIs.
- Preserve fixture-mode support for deterministic `test-sha256` signatures and
  keep production mode fail-closed for the local test signature kind.
- Preserve inner receipt payload bytes. The verifier may inspect payloads, but
  must not normalize or rewrite them.
- Preserve the current no-unsafe and no generated-code boundaries.
- Do not add real partner cryptographic attestation labels until the verifier
  actually implements those lanes.

## Affected Dependents

The only Rust workspace dependent is `xtask`, which uses the exporter and local
test signature helper to regenerate `tests/bindings/vectors/eval/v1.json`.
`cargo run -p xtask -- eval-receipt-regen --check` proves generator
compatibility.
