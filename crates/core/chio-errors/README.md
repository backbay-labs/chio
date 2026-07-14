# chio-errors

Typed Chio error codes and diagnostics: the `Domain` and `Severity` taxonomy
every Chio error is classified under, a `Code` string wrapper, the
`Diagnostic` / `ChioError` types that carry them, and a generated registry of
canonical `ErrorCodeSpec` entries with lookups by URN, string code, and
JSON-RPC numeric code.

Use it to raise or report a structured Chio error instead of an ad-hoc
string, so codes, domains, severities, and help text stay consistent across
the workspace. Prefer the `*_from_spec` constructors when the error has a
registered URN: they bind the registry's domain, severity, and help text to
the caller's message instead of letting the caller restate them.

## Responsibilities

- Define `Domain` (20 stable, `non_exhaustive` slugs) and `Severity`
  (`Info < Warning < Error < Fatal`), the two taxonomies every Chio error is
  classified under.
- Define `Code`, a serializable string wrapper for registry URNs and
  free-form diagnostic codes.
- Define `Diagnostic` and `ChioError`, which pair a code, domain, severity,
  and message with optional help text, plus a verified binding back to the
  registry (`registry_spec`).
- Own the generated error-code registry (`_generated::error_codes`, built
  from `spec/errors/registry.yaml` by `chio-spec-codegen`) and its lookups by
  URN, string code, and JSON-RPC numeric code.
- Bridge registry entries to wire-side JSON-RPC numeric codes
  (`jsonrpc_bridge`).

## Public API

- `Code` - serializable string wrapper (`Code::new`, `as_str`; `FromStr` is
  infallible).
- `Domain`, `Severity` - `as_str`, `lookup`, `FromStr` (`UnknownDomain` /
  `UnknownSeverity` preserve the rejected input); `Severity::rank` gives the
  ordinal behind its `Ord` impl.
- `Diagnostic`, `ChioError` - `new` (free-form) and `from_spec`
  (registry-bound) constructors, `with_help`, field accessors, and
  `registry_spec()` (`Some` only when the diagnostic's domain and severity
  still match the registry entry named by its code).
- `diagnostic`, `diagnostic_from_spec`, `error`, `error_from_spec` - function
  form of the constructors above.
- `_generated::error_codes` - `ErrorCodeSpec`, the `ERROR_CODES` table, and
  `lookup_error_code` / `lookup_string_code` / `lookup_string_code_matches` /
  `lookup_jsonrpc_code`. Only `ErrorCodeSpec`, `ERROR_CODES`, and the lookup
  functions are re-exported at the crate root; the 104 individual code
  constants (`CAPABILITY_EXPIRED`, `TRANSACTION_GRAPH_CYCLE`, ...) are
  reached through the full `_generated::error_codes` path.
- `jsonrpc_bridge::{to_jsonrpc_code, from_jsonrpc_code, round_trip_jsonrpc_code}`.
- `Result<T>` - alias for `std::result::Result<T, ChioError>`.

## Usage

```rust
use chio_errors::{error_from_spec, lookup_error_code};

let spec = match lookup_error_code("urn:chio:error:capability:expired") {
    Some(spec) => spec,
    None => panic!("registered code"),
};
let err = error_from_spec(spec, "token expired before evaluation");

assert_eq!(err.code().as_str(), spec.urn);
assert_eq!(err.help(), Some(spec.help));
```

## Testing

`cargo test -p chio-errors`

`tests/jsonrpc_bridge_property.rs` cross-checks every JSON-RPC-mapped
registry entry against the independently maintained wire fixture
`spec/errors/chio-error-registry.v1.json`.

## See also

- `chio-spec-codegen` - generates `_generated/error_codes.rs` from
  `spec/errors/registry.yaml`.
- `chio-cli`, `chio-control-plane`, `chio-lsp` - direct consumers of the
  typed error and registry surface.
