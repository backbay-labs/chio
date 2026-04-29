# Changelog

## Unreleased

- `chio-kernel` no longer enables `legacy-sync` by default. Downstream
  callers that still require the public `evaluate_tool_call_blocking` API must
  opt in with `--features legacy-sync` while migrating to `evaluate_tool_call`.
