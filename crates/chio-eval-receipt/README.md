# chio-eval-receipt

`chio-eval-receipt` is the reference verifier for
`chio.eval-report.bundle.v1` receipt bundles.

It verifies a bundle end to end:

- validates the bundle envelope against schema id `chio.eval-report.bundle.v1`
- recomputes the corpus SHA-256 and checks it against the bundle
- verifies the detached memo signature attached to each receipt

Verification fails closed: any envelope, corpus, or signature mismatch is
rejected.

## Library

- `verify_bundle` / `verify_fixture_bundle` parse and verify a bundle JSON
  document into a `VerifiedBundle`.
- `export_scenario_run` builds a `Bundle` from scenario inputs.

Schema details:

- schema id: `chio.eval-report.bundle.v1`
- schema path: `spec/eval/receipt-format.v1.json`

## CLI

The `chio-eval-receipt` binary verifies bundles and memo signatures:

- `chio-eval-receipt verify <bundle-path>`
- `chio-eval-receipt verify-fixture <bundle-path>`
- `chio-eval-receipt verify-memo <memo-path> <sig-path>`

## Python binding

The `py/` crate exposes `verify_bundle_json` through PyO3 for Python callers.
