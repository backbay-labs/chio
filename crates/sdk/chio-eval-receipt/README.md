# chio-eval-receipt

Reference verifier and unsigned exporter for `chio.eval-report.bundle.v1`
receipt bundles: partner-facing evidence packages that wrap signed Chio
tool-call receipts from the verdict-matrix conformance corpus. The crate has
no `chio-kernel` dependency and forbids `unsafe_code`; verification and
export operate purely on JSON documents and the inner receipt type from
`chio-core-types`.

## Responsibilities

- Validate a bundle envelope against a closed `chio.eval-report.bundle.v1`
  field set (unknown fields, missing required fields, and invalid enum
  values are all rejected) before trusting any content.
- Confirm the wrapped verdict-matrix corpus identity: `corpus.corpus_sha256`
  and `corpus.scenario_count` must match the compiled-in constants.
- Recompute each wrapped receipt's SHA-256 and verify its embedded
  `ChioReceipt` signature.
- Verify the outer bundle signature over the RFC 8785 canonical payload with
  `signatures` removed.
- Build an unsigned `Bundle` from validated scenario receipts and eval-run
  metadata (`export_scenario_run`); the exporter never signs.
- Expose the production verifier to Python via a PyO3 binding in `py/`.

## Public API

- `verify_bundle`, `verify_fixture_bundle` - parse and verify a bundle JSON
  document into a `VerifiedBundle`. Fixture mode additionally accepts the
  deterministic `test-sha256` outer signature and a closed set of local
  fixture receipts.
- `test_signature_for_bundle_json` - compute the deterministic fixture
  signature for a bundle document.
- `export_scenario_run` - build an unsigned `Bundle` from `Receipt`s and an
  `EvalRunMeta`.
- `EvalRunMeta::from_parts`, `Receipt::from_parts` - validate borrowed
  `EvalRunMetaParts` / `ReceiptParts` into owned fields, rejecting empty or
  padded identity fields via `ExportError`.
- Bundle types: `Bundle`, `Producer`, `Corpus`, `ReceiptEntry`,
  `ReceiptEvidence`, `VerifiedBundle`.
- Errors: `BundleError`, `ExportError`.
- Constants: `BUNDLE_SCHEMA_ID`, `BUNDLE_SCHEMA_PATH`,
  `VERDICT_MATRIX_CORPUS_SHA256`, `VERDICT_MATRIX_SCENARIO_COUNT`,
  `VERDICT_MATRIX_MANIFEST_PATH`.

`src/bin/cli.rs` builds the `chio-eval-receipt` binary:

| Command | Effect |
|---------|--------|
| `verify <bundle-path>` | Production verification via `verify_bundle`. |
| `verify-fixture <bundle-path>` | Fixture-mode verification via `verify_fixture_bundle`. |
| `verify-memo <memo-path> <sig-path>` | Checks a detached `chio-memo-signature.v1` sig file against a memo file, using a self-generated SHA-256 scheme (`synthetic-test-sample`) that is explicitly not a real cryptographic attestation. |

## Testing

`cargo test -p chio-eval-receipt` runs the unit and integration tests
(`tests/export_roundtrip.rs`, `tests/schema_lint.rs`), including a check that
the golden vector `tests/bindings/vectors/eval/v1.json` still verifies.

`py/` is excluded from the default workspace; build it with `maturin
develop` and run `pytest py/tests`.

The `fuzz` workspace member fuzzes `verify_bundle`
(`fuzz/fuzz_targets/eval_receipt_bundle.rs`).

## See also

- `chio-core-types` - supplies RFC 8785 canonicalization and the inner
  `ChioReceipt` signature check this crate verifies against.
- `chio-eval-receipt-py` (`py/`) - PyO3 binding over `verify_bundle`, built
  separately via maturin.
- `xtask` - regenerates the golden vector
  `tests/bindings/vectors/eval/v1.json` through this crate's exporter
  (`eval-receipt-regen`).
