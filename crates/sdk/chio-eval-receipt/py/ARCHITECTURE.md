# chio-eval-receipt-py architecture

## Overview

`chio-eval-receipt-py` is a thin PyO3 binding over `chio-eval-receipt`. It
holds no verification logic of its own: the exported function forwards its
input to the parent crate and translates the Rust result into a Python
return value or a raised exception. The crate builds as a `cdylib` Python
extension module through maturin and is excluded from the default Cargo
workspace, which builds and lints the rest of the repo with `cargo`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | The `verify_bundle_json` PyO3 function and the `chio_eval_receipt_py` module definition. |

## Request lifecycle

1. Python calls `chio_eval_receipt_py.verify_bundle_json(bundle_json)` with a
   JSON string.
2. The binding forwards the string unchanged to
   `chio_eval_receipt::verify_bundle`.
3. On success, it formats the returned `VerifiedBundle` into one summary
   string (`bundle_id`, `receipt_count`, `signature_count`, `corpus_sha256`)
   and returns it to Python.
4. On error, it converts the `chio_eval_receipt` error to its `Display`
   string and raises it as a Python `ValueError` (`PyValueError`).

## Invariants and failure modes

- Only production verification (`verify_bundle`) is reachable from Python;
  `verify_fixture_bundle` has no binding here.
- The crate inherits the workspace clippy lint set (`[lints] workspace =
  true`), which denies `unwrap_used`/`expect_used`; the binding satisfies
  this by mapping every error through `PyValueError` instead of panicking.
- The binding performs no independent validation. It fails exactly when
  `chio_eval_receipt::verify_bundle` fails, with the same error message.

## Dependencies

`chio-eval-receipt` (path dependency on the parent crate) supplies
`verify_bundle` and `VerifiedBundle`. `pyo3` (`auto-initialize` feature)
supplies the Python binding layer. `[lib] crate-type = ["cdylib", "rlib"]`:
`cdylib` produces the `chio_eval_receipt_py` extension module maturin ships;
`rlib` lets the crate also be linked as an ordinary Rust dependency.
