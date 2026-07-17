# chio-errors architecture

## Overview

`chio-errors` is a pure type and data crate: no I/O, no runtime state,
`#![forbid(unsafe_code)]`, and no internal `chio-*` dependencies, so it sits
at the base of the dependency graph alongside `chio-core-types`. It owns the
`Domain` / `Severity` / `Code` taxonomy every Chio error is classified under,
the `Diagnostic` / `ChioError` types that carry them, and a registry of
canonical `ErrorCodeSpec` entries generated from `spec/errors/registry.yaml`.
The core design idea is the split between free-form construction, which
accepts any code, domain, severity, and message, and registry-verified
construction and lookup, which cannot silently drift from the registry entry
it names.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root: `#![forbid(unsafe_code)]`, module declarations, the top-level `pub use` surface, and the `Result<T>` alias. |
| `src/code.rs` | `Code`, a serializable string wrapper for diagnostic codes. |
| `src/domain.rs` | `Domain` (20-variant, `non_exhaustive`, stable slugs) and `UnknownDomain`. |
| `src/severity.rs` | `Severity` (`Info < Warning < Error < Fatal`, ordered) and `UnknownSeverity`. |
| `src/diagnostic.rs` | `Diagnostic` and `ChioError`: construction, `Display` formatting, registry-verified binding (`registry_spec`), and the `diagnostic` / `error` / `*_from_spec` free functions. |
| `src/jsonrpc_bridge.rs` | Conversion between `ErrorCodeSpec` and wire-side JSON-RPC numeric codes. |
| `src/_generated/error_codes.rs` | Generated from `spec/errors/registry.yaml` by `chio-spec-codegen`: `ErrorCodeSpec`, 104 per-error constants, the `ERROR_CODES` table, and the `lookup_*` functions. Not hand-edited. |
| `src/_generated/mod.rs` | Declares the generated `error_codes` submodule. |

## Registry binding

- Free-form path: `Diagnostic::new` / `diagnostic()` and `ChioError::new` /
  `error()` take a code, domain, severity, and message directly. No registry
  check happens; any `Code` value, including an unregistered or malformed
  one, is accepted.
- Registry-bound path: `Diagnostic::from_spec` / `diagnostic_from_spec()` and
  `ChioError::from_spec` / `error_from_spec()` take an `&ErrorCodeSpec` and a
  local message. The code, domain, severity, and help text come from the
  spec; the caller supplies only the message.
- Verified lookup: `registry_spec()` looks up the diagnostic's stored code in
  `ERROR_CODES` via `lookup_error_code` and returns the entry only if the
  diagnostic's stored domain and severity both equal the entry's. A
  diagnostic built free-form with a registered URN but a mismatched domain or
  severity resolves to `None`, not a corrected entry.
- Keyed views over `ERROR_CODES`: `lookup_error_code` by URN,
  `lookup_jsonrpc_code` by wire numeric code, and `lookup_string_code` by
  legacy string code. `lookup_string_code` fails closed to `None` when more
  than one entry shares a string code (the registry currently has one such
  duplicate, `CHIO-CLI-JSON`, shared by two entries); `lookup_string_code_matches`
  is the only way to enumerate every collision.

## Invariants and failure modes

- `registry_spec()` requires an exact domain and severity match against the
  registry entry named by the diagnostic's code; it never substitutes the
  registry's values over a mismatched local diagnostic.
- `lookup_string_code` returns `None` rather than an arbitrary first match
  when a string code is ambiguous.
- `Domain` is `#[non_exhaustive]`; matches on it must handle future variants.
- `Code::from_str` is infallible; `Domain::from_str` and `Severity::from_str`
  reject unknown input and preserve it on `UnknownDomain` / `UnknownSeverity`
  for error reporting.
- `_generated/*` is produced by `chio-spec-codegen` from
  `spec/errors/registry.yaml` (`cargo run -p chio-spec-codegen --
  --errors-only`); its header comment marks it DO NOT EDIT.
- Every lookup is a linear scan over the static `ERROR_CODES` slice; there is
  no index and no allocation on the read path.

## Dependencies

No internal `chio-*` dependencies. External: `serde` for `Serialize` /
`Deserialize` on `Code`, `Domain`, `Severity`, `Diagnostic`, and `ChioError`;
`thiserror` for the `UnknownDomain`, `UnknownSeverity`, and `ChioError` error
derives.
