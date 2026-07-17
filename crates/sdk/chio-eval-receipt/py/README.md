# chio-eval-receipt-py

PyO3 binding that exposes `chio-eval-receipt`'s bundle verifier to Python. It
wraps a single function, `verify_bundle_json`, and adds no verification logic
of its own. Builds as a `cdylib` Python extension module via maturin;
excluded from the default Cargo workspace.

## Responsibilities

- Wrap `chio_eval_receipt::verify_bundle` as a Python-callable function that
  raises `ValueError` instead of returning a Rust `Result`.
- Register the `chio_eval_receipt_py` PyO3 module and the one function it
  exposes.

## Public API

- `verify_bundle_json(bundle_json: str) -> str` - production-verifies
  (`verify_bundle`, not fixture mode) a `chio.eval-report.bundle.v1` JSON
  document and returns a summary string: `bundle_id=... receipts=...
  signatures=... corpus_sha256=...`. Raises `ValueError` on any verification
  failure.

## Usage

```python
import chio_eval_receipt_py

summary = chio_eval_receipt_py.verify_bundle_json(bundle_json_text)
```

## Testing

Excluded from the default Cargo workspace (see the root `Cargo.toml`
`exclude` list); build and test through maturin and pytest:

```bash
maturin develop
pytest tests/
```

`tests/test_smoke.py` checks that an invalid bundle document raises
`ValueError` rather than returning a summary.

## See also

- `chio-eval-receipt` - the parent crate; owns bundle parsing, verification,
  and unsigned export. This crate wraps its `verify_bundle` entry point only.
