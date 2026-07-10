# chio-errors

`chio-errors` defines Chio's typed error codes and diagnostics. It exposes the
`Code` and `Domain` taxonomy, the `ChioError` / `Diagnostic` types, severity
levels, a JSON-RPC bridge, and a generated registry of error-code specs with
lookups by canonical code, JSON-RPC code, and compatibility string code.

Use this crate when you need to emit or interpret a structured Chio error
rather than an ad-hoc string, so diagnostics stay consistent across the
workspace.

For registered errors, prefer `Diagnostic::from_spec`, `ChioError::from_spec`,
`diagnostic_from_spec`, or `error_from_spec`. Those constructors bind the
registry entry's URN, domain, severity, and help text to the caller's local
message, while the free-form constructors remain available for compatibility or
unregistered surfaces.

Use `lookup_error_code` for direct registry queries by URN. Use
`Diagnostic::registry_spec` or `ChioError::registry_spec` when reporting a
diagnostic as registry-bound, because those methods verify that the diagnostic's
domain and severity still match the registry entry it names.
