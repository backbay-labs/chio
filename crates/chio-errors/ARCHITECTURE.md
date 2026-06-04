# chio-errors Architecture

## Boundary

`chio-errors` owns the typed Chio error taxonomy and diagnostic construction
surface. It exposes canonical `Domain`, `Severity`, `Code`, `Diagnostic`, and
`ChioError` types, plus lookup access to the generated error registry and the
JSON-RPC bridge. It does not decide policy, evaluate guards, format CLI output,
or translate transport status codes. Callers should bring domain context and
message text; this crate should bind those messages to stable Chio registry
metadata when a registry entry exists.

## Module Boundaries

- `code` owns the serializable diagnostic code string wrapper.
- `domain` owns stable error-domain slugs and parsing.
- `severity` owns severity ordering and parsing.
- `diagnostic` owns the structured diagnostic and error types.
- `jsonrpc_bridge` owns conversion between registry entries and wire-side
  JSON-RPC numeric codes.
- `_generated::error_codes` is generated from `spec/errors/registry.yaml` by
  `chio-spec-codegen` and must not be edited directly.

## Pain Points

- Registry entries already carry canonical URN, domain, severity, summary, help,
  stability, string-code, and JSON-RPC metadata.
- Registry-bound constructors now centralize the common
  `ErrorCodeSpec` plus caller message path, but free-form constructors can still
  create a diagnostic whose code is a registered URN while its domain or
  severity disagrees with the registry.
- A code-only registry lookup is useful for hovers and direct registry queries,
  but treating a mismatched diagnostic as registry-bound can attach stable
  string-code, stability, or help metadata to a contradictory local error.
- Generated lookup helpers are intentionally simple. Non-generated diagnostic
  APIs should own the stronger "is this diagnostic actually bound to the
  registry entry it names" rule.

## Security And API Constraints

- Preserve public API compatibility for `Code::new`, `diagnostic`, `error`,
  registry lookup functions, and generated `ErrorCodeSpec` constants.
- Do not edit `_generated` files directly. Registry data changes must go through
  `spec/errors/registry.yaml` and `chio-spec-codegen`.
- Diagnostics built from registry entries must use the registry's URN, domain,
  severity, and help text without allowing callers to accidentally mismatch
  those fields.
- Unknown free-form codes must remain representable for legacy CLI and transport
  surfaces.
- JSON-RPC bridge behavior must remain fail-closed for unmapped numeric codes.

## Affected Dependents

Direct dependents include `chio-cli`, `chio-control-plane`, and `chio-lsp`.
Downstream consumers through `chio-control-plane` include `chio-hosted-mcp`,
`chio-mcp-remote`, `chio-conformance`, `chio-mercury`, and `chio-wall`.
The diagnostic API keeps its return type, but `chio-control-plane` reporting
must use the verified method so it does not attach registry metadata to a
mismatched diagnostic by raw code alone.

## Planned Improvement

Make diagnostic registry binding verified rather than code-only. Keep
`lookup_error_code` available for direct registry lookup, but make
`Diagnostic::registry_spec` and `ChioError::registry_spec` return a registry
entry only when the diagnostic code, domain, and severity all match that entry.

This is architectural because it defines the ownership boundary between raw
registry queries and typed diagnostic binding. Dependents that report
`ChioError` metadata should use the verified method instead of reattaching
registry metadata by code alone.
