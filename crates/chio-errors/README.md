# chio-errors

`chio-errors` defines Chio's typed error codes and diagnostics. It exposes the
`Code` and `Domain` taxonomy, the `ChioError` / `Diagnostic` types, severity
levels, a JSON-RPC bridge, and a generated registry of error-code specs with
lookups by canonical code, JSON-RPC code, and legacy string code.

Use this crate when you need to emit or interpret a structured Chio error
rather than an ad-hoc string, so diagnostics stay consistent across the
workspace.
