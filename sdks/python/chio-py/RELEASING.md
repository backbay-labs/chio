# Releasing `chio-sdk`

`chio-sdk` is the distribution name. The import package is `chio`.

## Release Gate

Run these commands from the repo root:

```sh
./scripts/check-chio-py.sh
./scripts/check-chio-py-release.sh
./scripts/check-sdk-publication-examples.sh
```

The release qualification scripts verify:

- the declared version in `pyproject.toml` matches `src/chio/version.py`
- wheel and sdist artifacts build cleanly
- package metadata passes `twine check`
- wheel and sdist both install into clean virtual environments
- the installed distribution reports version `chio-sdk == chio.__version__`
- the built artifacts include `chio/py.typed`
- the source distribution excludes stale cache artifacts and stale egg-info
  metadata
- clean installs expose `ChioClient`, `ChioSession`, and `ReceiptQueryClient`

## Expected Artifacts

- wheel: `chio_sdk-<version>-py3-none-any.whl`
- source distribution: `chio_sdk-<version>.tar.gz`

## Publication Notes

- `chio-sdk` is the `0.1.0` (pre-release) Python publication target for Chio's hosted
  MCP and receipt-query surface.
- The package stays pure Python and does not require a Rust toolchain.
- The API is intentionally narrow: remote MCP sessions, receipt queries,
  invariants, and auth helpers.
